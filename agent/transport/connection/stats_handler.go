package connection

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/stats"
)

var (
	DefaultStatsHandler = StatsHandler{
		updateTime: time.Now(),
	}
)

type StatsHandler struct {
	rxBytes    uint64
	txBytes    uint64
	updateTime time.Time
}
type Stats struct {
	RxSpeed float64
	TxSpeed float64
}

func (h *StatsHandler) GetStats(now time.Time) (s Stats) {
	instant := now.Sub(h.updateTime).Seconds()
	if instant != 0 {
		s.RxSpeed = float64(atomic.SwapUint64(&h.rxBytes, 0)) / (float64(instant))
		s.TxSpeed = float64(atomic.SwapUint64(&h.txBytes, 0)) / (float64(instant))
		h.updateTime = now
	}
	return
}
func (h *StatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	// no-op
	return ctx
}
func (h *StatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	switch s := s.(type) {
	case *stats.InPayload:
		atomic.AddUint64(&h.rxBytes, uint64(s.WireLength))
	case *stats.OutPayload:
		atomic.AddUint64(&h.txBytes, uint64(s.WireLength))
	}
}
func (h *StatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	// no-op
	return ctx
}
func (h *StatsHandler) HandleConn(ctx context.Context, _ stats.ConnStats) {
	// no-op
}
