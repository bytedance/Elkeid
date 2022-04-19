package transport

import (
	"context"
	"sync"

	_ "github.com/bytedance/Elkeid/agent/transport/compressor"
	"go.uber.org/zap"
)

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	zap.S().Info("transport daemon startup")
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	subWg := &sync.WaitGroup{}
	defer subWg.Wait()
	subWg.Add(2)
	go startFileExt(subCtx, subWg)
	go func() {
		startTransfer(subCtx, subWg)
		cancel()
	}()
}
