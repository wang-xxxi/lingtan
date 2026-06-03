"""扫描断点续传 — 保存/恢复扫描进度"""
import json
import uuid
import time


class ScanCheckpoint:
    """扫描检查点管理器"""

    def __init__(self, db):
        """
        Args:
            db: Database 实例 (core.database.Database)
        """
        self.db = db

    def create(self, scan_type, target_url, initial_state=None):
        """创建新的扫描检查点

        Args:
            scan_type: 'crawl' / 'site_crawl' / 'security_scan'
            target_url: 扫描目标 URL
            initial_state: 初始状态 dict

        Returns:
            str: checkpoint_id (UUID)
        """
        checkpoint_id = str(uuid.uuid4())
        state = initial_state or {
            'queue': [],
            'visited': [],
            'current_phase': 'init',
            'phase_progress': 0,
            'total_found': 0,
        }
        self.db.execute(
            '''INSERT INTO scan_checkpoints
               (checkpoint_id, scan_type, target_url, state, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (checkpoint_id, scan_type, target_url, json.dumps(state, ensure_ascii=False),
             int(time.time()), int(time.time()))
        )
        return checkpoint_id

    def update(self, checkpoint_id, state):
        """更新检查点状态

        Args:
            checkpoint_id: 检查点 ID
            state: 新的状态 dict
        """
        self.db.execute(
            '''UPDATE scan_checkpoints
               SET state = ?, updated_at = ?
               WHERE checkpoint_id = ?''',
            (json.dumps(state, ensure_ascii=False), int(time.time()), checkpoint_id)
        )

    def update_progress(self, checkpoint_id, visited=None, queue=None,
                        phase=None, progress=None, total_found=None):
        """增量更新检查点（方便调用）"""
        current = self.load(checkpoint_id)
        if not current:
            return
        state = current['state']
        if visited is not None:
            if isinstance(visited, list):
                state['visited'] = list(set(state.get('visited', []) + visited))
            else:
                vs = state.get('visited', [])
                if visited not in vs:
                    vs.append(visited)
                state['visited'] = vs
        if queue is not None:
            state['queue'] = queue
        if phase is not None:
            state['current_phase'] = phase
        if progress is not None:
            state['phase_progress'] = progress
        if total_found is not None:
            state['total_found'] = total_found
        self.update(checkpoint_id, state)

    def load(self, checkpoint_id):
        """加载检查点

        Returns:
            dict: {checkpoint_id, scan_type, target_url, state, created_at, updated_at}
                  或 None（不存在）
        """
        rows = self.db.fetch_all(
            'SELECT * FROM scan_checkpoints WHERE checkpoint_id = ?',
            (checkpoint_id,)
        )
        if not rows:
            return None
        row = rows[0]
        return {
            'checkpoint_id': row['checkpoint_id'],
            'scan_type': row['scan_type'],
            'target_url': row['target_url'],
            'state': json.loads(row['state']),
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        }

    def list_active(self, max_age_hours=24):
        """列出可恢复的检查点

        Args:
            max_age_hours: 最大保留时间（小时）

        Returns:
            list[dict]: 可恢复的检查点列表
        """
        cutoff = int(time.time()) - max_age_hours * 3600
        rows = self.db.fetch_all(
            '''SELECT * FROM scan_checkpoints
               WHERE updated_at > ?
               ORDER BY updated_at DESC''',
            (cutoff,)
        )
        results = []
        for row in rows:
            state = json.loads(row['state'])
            results.append({
                'checkpoint_id': row['checkpoint_id'],
                'scan_type': row['scan_type'],
                'target_url': row['target_url'],
                'visited_count': len(state.get('visited', [])),
                'queue_count': len(state.get('queue', [])),
                'current_phase': state.get('current_phase', ''),
                'total_found': state.get('total_found', 0),
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
            })
        return results

    def delete(self, checkpoint_id):
        """删除检查点"""
        self.db.execute(
            'DELETE FROM scan_checkpoints WHERE checkpoint_id = ?',
            (checkpoint_id,)
        )

    def cleanup(self, max_age_hours=48):
        """清理过期检查点"""
        cutoff = int(time.time()) - max_age_hours * 3600
        self.db.execute(
            'DELETE FROM scan_checkpoints WHERE updated_at < ?',
            (cutoff,)
        )

    def get_visited(self, checkpoint_id):
        """获取已扫描的 URL 列表"""
        cp = self.load(checkpoint_id)
        if cp:
            return cp['state'].get('visited', [])
        return []

    def get_queue(self, checkpoint_id):
        """获取待扫描队列"""
        cp = self.load(checkpoint_id)
        if cp:
            return cp['state'].get('queue', [])
        return []
