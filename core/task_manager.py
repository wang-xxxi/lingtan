"""Unified task queue manager"""
import threading
import time
import uuid
import json
from concurrent.futures import ThreadPoolExecutor


class TaskManager:
    """Manage background tasks with unified state tracking"""

    def __init__(self, db, max_workers=3):
        self.db = db
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks = {}  # task_id -> task state dict
        self._lock = threading.Lock()
        self._callbacks = {}  # task_id -> stop_event

    def submit(self, task_type, target, func, params=None):
        """Submit a new task. Returns task_id."""
        task_id = str(uuid.uuid4())[:8]
        now = time.time()

        task = {
            'id': task_id,
            'type': task_type,
            'target': target,
            'status': 'pending',
            'progress': 0,
            'message': 'Queued',
            'result': None,
            'params': params or {},
            'created_at': now,
            'started_at': None,
            'finished_at': None,
            'error': None,
        }

        with self._lock:
            self._tasks[task_id] = task

        # Save to database
        try:
            self.db.add_task(task_id, task_type, target, params or {})
        except Exception:
            pass

        # Create stop event for this task
        stop_event = threading.Event()
        self._callbacks[task_id] = stop_event

        # Wrapper to update state
        def run_task():
            with self._lock:
                self._tasks[task_id]['status'] = 'running'
                self._tasks[task_id]['started_at'] = time.time()
                self._tasks[task_id]['message'] = 'Running...'

            try:
                self._update_db(task_id, 'running', 0, 'Running...')
                result = func(task_id=task_id, stop_event=stop_event,
                              progress_callback=lambda m, p: self._update_progress(task_id, m, p))
                with self._lock:
                    self._tasks[task_id]['status'] = 'completed'
                    self._tasks[task_id]['progress'] = 100
                    self._tasks[task_id]['message'] = 'Completed'
                    self._tasks[task_id]['result'] = result
                    self._tasks[task_id]['finished_at'] = time.time()
                self._update_db(task_id, 'completed', 100, 'Completed', result)
            except Exception as e:
                with self._lock:
                    self._tasks[task_id]['status'] = 'failed'
                    self._tasks[task_id]['error'] = str(e)
                    self._tasks[task_id]['message'] = f'Error: {e}'
                    self._tasks[task_id]['finished_at'] = time.time()
                self._update_db(task_id, 'failed', self._tasks[task_id]['progress'], str(e))

        self.executor.submit(run_task)
        return task_id

    def get(self, task_id):
        """Get task state by ID"""
        with self._lock:
            return dict(self._tasks.get(task_id, {}))

    def list_tasks(self, limit=50):
        """List all tasks"""
        with self._lock:
            tasks = sorted(self._tasks.values(), key=lambda t: t['created_at'], reverse=True)
            return [dict(t) for t in tasks[:limit]]

    def stop(self, task_id):
        """Stop a running task"""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False, 'Task not found'
            if task['status'] != 'running':
                return False, f'Task is {task["status"]}'

        stop_event = self._callbacks.get(task_id)
        if stop_event:
            stop_event.set()

        with self._lock:
            self._tasks[task_id]['status'] = 'stopped'
            self._tasks[task_id]['message'] = 'Stopped by user'
            self._tasks[task_id]['finished_at'] = time.time()

        self._update_db(task_id, 'stopped', self._tasks[task_id].get('progress', 0), 'Stopped')
        return True, 'Task stopped'

    def _update_progress(self, task_id, message, progress):
        """Update task progress"""
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id]['message'] = message
                if progress is not None:
                    self._tasks[task_id]['progress'] = progress

    def _update_db(self, task_id, status, progress, message, result=None):
        """Update task in database"""
        try:
            self.db.update_task(task_id, status, progress, message, result)
        except Exception:
            pass

    def has_active_tasks(self):
        """Check if any tasks are running"""
        with self._lock:
            return any(t['status'] == 'running' for t in self._tasks.values())

    def active_count(self):
        """Count running tasks"""
        with self._lock:
            return sum(1 for t in self._tasks.values() if t['status'] == 'running')
