package proxy

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codex2api/auth"
)

var strictTurnStateRefreshHandler atomic.Pointer[Handler]

// 每账号只有一个队列；同模型共享结果，不同模型串行占用同一个探测槽位。
// 引用计数只取消无人等待的模型；Stop 和服务退出则取消整个队列。
type strictTurnStateTask struct {
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	queue   []*strictTurnStateModelTask
	models  map[string]*strictTurnStateModelTask
}

type strictTurnStateModelTask struct {
	ctx      context.Context
	cancel   context.CancelFunc
	model    string
	proxy    string
	refs     int
	done     chan struct{}
	finished bool
	state    string
	err      error
}

func refreshCodexTurnStateForStrictRequest(ctx context.Context, account *auth.Account, model, proxyOverride string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	h := strictTurnStateRefreshHandler.Load()
	if h == nil || h.store == nil {
		return "", fmt.Errorf("严格 turn-state 刷新 handler 未就绪")
	}
	if account == nil {
		return "", fmt.Errorf("账号为空")
	}
	model = strings.TrimSpace(model)
	if model == "" || strings.ContainsAny(model, "*, \t\r\n") {
		return "", fmt.Errorf("严格刷新需要实际请求模型，不能使用模型范围")
	}
	id := account.ID()
	if _, err := h.turnStateProbeAccount(id, true); err != nil {
		return "", err
	}
	r := h.turnStateRefresher()
	r.mu.Lock()
	if err := r.lifecycle.Err(); err != nil {
		r.mu.Unlock()
		return "", err
	}
	task := r.strict[id]
	if task == nil {
		taskCtx, cancel := context.WithCancel(r.lifecycle)
		task = &strictTurnStateTask{ctx: taskCtx, cancel: cancel, models: make(map[string]*strictTurnStateModelTask)}
		r.strict[id] = task
		go h.runStrictTurnStateTask(id, task)
	}
	if err := task.ctx.Err(); err != nil {
		r.mu.Unlock()
		return "", err
	}
	job := task.models[model]
	if job == nil || job.ctx.Err() != nil {
		jobCtx, cancel := context.WithCancel(task.ctx)
		job = &strictTurnStateModelTask{ctx: jobCtx, cancel: cancel, model: model, proxy: proxyOverride, done: make(chan struct{})}
		task.models[model] = job
		task.queue = append(task.queue, job)
	}
	job.refs++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		job.refs--
		if job.refs == 0 && !job.finished {
			job.cancel()
		}
		anyWaiting := false
		for _, queued := range task.models {
			if queued.refs > 0 && !queued.finished {
				anyWaiting = true
				break
			}
		}
		if !anyWaiting {
			task.cancel()
			// 同锁撤下取消任务；新请求等待旧running/done释放后再起，不能继承取消。
			if r.strict[id] == task {
				delete(r.strict, id)
			}
		}
		r.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-task.ctx.Done():
	case <-job.done:
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// 正常队列回收也会cancel task；不能因此把已持久化的结果误判成取消。
	if task.stopped {
		return "", context.Canceled
	}
	if job.finished {
		return job.state, job.err
	}
	return "", task.ctx.Err()
}

func (h *Handler) runStrictTurnStateTask(id int64, task *strictTurnStateTask) {
	r := h.turnStateRefresher()
	// 等待后台任务时也观察授权，不能抢占后台 refine 或用它的其它模型结果放行。
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-task.ctx.Done():
				return
			case <-ticker.C:
				if _, err := h.turnStateProbeAccount(id, true); err != nil {
					task.cancel()
					return
				}
			}
		}
	}()
	owned := false
	defer func() {
		r.mu.Lock()
		for _, job := range task.models {
			if !job.finished {
				job.err = task.ctx.Err()
				if job.err == nil {
					job.err = context.Canceled
				}
				job.finished = true
				job.cancel()
				close(job.done)
			}
		}
		if owned {
			delete(r.running, id)
			delete(r.refineProbes, id)
			close(r.done[id])
			delete(r.done, id)
		}
		if r.strict[id] == task {
			delete(r.strict, id)
		}
		r.mu.Unlock()
		task.cancel()
		<-watchDone
	}()
	for !owned {
		r.mu.Lock()
		if task.ctx.Err() != nil {
			r.mu.Unlock()
			return
		}
		if !r.running[id] {
			r.running[id] = true
			r.done[id] = make(chan struct{})
			r.refineProbes[id] = 0
			owned = true
			r.mu.Unlock()
			break
		}
		done := r.done[id]
		r.mu.Unlock()
		select {
		case <-task.ctx.Done():
			return
		case <-done:
		}
	}
	for {
		r.mu.Lock()
		if task.ctx.Err() != nil {
			r.mu.Unlock()
			return
		}
		if len(task.queue) == 0 {
			// 保持锁直到撤掉入口，避免新请求加入已决定退出的队列。
			delete(r.strict, id)
			r.mu.Unlock()
			return
		}
		job := task.queue[0]
		task.queue = task.queue[1:]
		r.mu.Unlock()
		state, err := h.probeCodexTurnStateUntilGood(job.ctx, id, job.model, job.proxy, true)
		r.mu.Lock()
		job.state, job.err, job.finished = state, err, true
		if task.models[job.model] == job {
			delete(task.models, job.model)
		}
		job.cancel()
		close(job.done)
		r.mu.Unlock()
	}
}
