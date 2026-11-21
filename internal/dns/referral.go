package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// AskDelegation asks server ("ip:port"), which should be authoritative for a
// zone above name, for name's NS records without asking it to recurse, and
// returns the name servers it delegates name to (#406): the NS records owned
// by name, from the answer section or, in a referral, the authority section.
// No such records (the name is not a delegation, or the server answered
// for it itself) is an empty list and no error; an error RCODE is an error.
// It sends one query over UDP, and one more over TCP if the answer was
// truncated, each paced by the rate limiter on ctx and counted by its query
// counter (WithLimiter, WithQueryCounter), and reports how many it sent.
func AskDelegation(ctx context.Context, server, name string, timeout time.Duration) (hosts []string, sent int, err error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	id := uint16(rand.UintN(1 << 16)) //nolint:gosec // a DNS message ID, not a secret
	query, err := delegationQuery(id, name+".")
	if err != nil {
		return nil, 0, err
	}
	ask := func(network string) ([]byte, error) {
		if err := limiterFrom(ctx).Wait(ctx); err != nil {
			return nil, err
		}
		if c, ok := ctx.Value(queryCounterKey{}).(*atomic.Int64); ok {
			c.Add(1)
		}
		sent++
		qctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return exchange(qctx, network, server, query)
	}
	resp, err := ask("udp")
	if err == nil && truncated(resp) {
		resp, err = ask("tcp")
	}
	if err != nil {
		return nil, sent, err
	}
	hosts, err = readDelegation(resp, id, name)
	return hosts, sent, err
}

// delegationQuery is an NS query for name with recursion not desired.
func delegationQuery(id uint16, name string) ([]byte, error) {
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// maxDelegationHosts bounds the name servers readDelegation keeps, so a
// hostile answer cannot make a scan look up thousands of hosts.
const maxDelegationHosts = 16

// readDelegation returns the hosts of the NS records owned by name in msg's
// answer and authority sections, lower case, without the trailing dot and
// without repeats.
func readDelegation(msg []byte, id uint16, name string) ([]string, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if h.ID != id || !h.Response {
		return nil, errors.New("delegation check: unexpected message")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("delegation check: %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var hosts []string
	keep := func(rh dnsmessage.ResourceHeader, ns func() (dnsmessage.NSResource, error), skip func() error) error {
		owner := strings.ToLower(strings.TrimSuffix(rh.Name.String(), "."))
		if rh.Type != dnsmessage.TypeNS || owner != name || len(hosts) >= maxDelegationHosts {
			return skip()
		}
		r, err := ns()
		if err != nil {
			return err
		}
		host := strings.ToLower(strings.TrimSuffix(r.NS.String(), "."))
		if host != "" && !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
		return nil
	}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := keep(rh, p.NSResource, p.SkipAnswer); err != nil {
			return nil, err
		}
	}
	for {
		rh, err := p.AuthorityHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return hosts, nil
		}
		if err != nil {
			return nil, err
		}
		if err := keep(rh, p.NSResource, p.SkipAuthority); err != nil {
			return nil, err
		}
	}
}

// WaitRate takes n slots of the rate limiter on ctx (WithLimiter), for
// queries sent by a resolver that does not take them itself; without a
// limiter it only reports whether ctx is done.
func WaitRate(ctx context.Context, n int) error {
	l := limiterFrom(ctx)
	for range n {
		if err := l.Wait(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}
