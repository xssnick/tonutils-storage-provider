package service

import (
	"context"
	"errors"
	"github.com/xssnick/tonutils-go/ton/wallet"
)

// TxQueue serializes wallet transactions so they are sent one-by-one from a single goroutine
// while allowing callers (possibly many goroutines) to wait for their own results.
// It prevents concurrent SendWaitTransaction calls on the same wallet, which may
// cause nonce/seqno races or other issues.
//
// Usage:
//   hash, err := q.SendWait(ctx, wallet.SimpleMessage(addr, amount, payload))
//
// The queue must be created with NewTxQueue and will run an internal worker until the context is cancelled.
// Cancelling the provided context to NewTxQueue will stop the queue and unblock pending callers with ctx errors.
// Individual SendWait contexts are still respected for cancellation/timeouts.

type TxQueue struct {
	w      *wallet.Wallet
	reqCh  chan txRequest
	closed chan struct{}
}

type txRequest struct {
	ctx  context.Context
	msg  *wallet.Message
	resp chan txResponse
}

type txResponse struct {
	hash []byte
	err  error
}

// NewTxQueue creates a TxQueue bound to the given wallet and starts a single worker
// that processes requests sequentially until ctx is cancelled.
func NewTxQueue(ctx context.Context, w *wallet.Wallet) *TxQueue {
	q := &TxQueue{
		w:      w,
		reqCh:  make(chan txRequest),
		closed: make(chan struct{}),
	}

	go q.loop(ctx)
	return q
}

func (q *TxQueue) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			q.shutdown(ctx)
			return
		case req := <-q.reqCh:
			if req.ctx.Err() != nil {
				select {
				case req.resp <- txResponse{err: req.ctx.Err()}:
				case <-ctx.Done():
				}
				continue
			}

			tx, _, err := q.w.SendWaitTransaction(req.ctx, req.msg)

			var hash []byte
			if err == nil && tx != nil {
				hash = tx.Hash
			}

			select {
			case req.resp <- txResponse{hash: hash, err: err}:
			case <-req.ctx.Done():
			case <-ctx.Done():
				q.shutdown(ctx)
				return
			}
		}
	}
}

func (q *TxQueue) shutdown(ctx context.Context) {
	close(q.closed)

	for {
		select {
		case req := <-q.reqCh:
			select {
			case req.resp <- txResponse{err: ctx.Err()}:
			default:
			}
		default:
			return
		}
	}
}

// SendWait enqueues the message and waits for the transaction result.
// If the queue is already stopped, it returns context.Canceled-like error.
func (q *TxQueue) SendWait(ctx context.Context, msg *wallet.Message) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("nil wallet message")
	}
	respCh := make(chan txResponse, 1)
	req := txRequest{ctx: ctx, msg: msg, resp: respCh}

	select {
	case q.reqCh <- req:
		// enqueued
	case <-q.closed:
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case r := <-respCh:
		return r.hash, r.err
	case <-q.closed:
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
