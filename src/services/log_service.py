"""
log_service.py - Versleutelde activiteitenlogging.

Elke betekenisvolle actie roept LogService.log(...) aan. De repository
versleutelt de regel voordat hij de schijf raakt.
"""

from datetime import datetime

from data.repositories import LogRepository


class LogService:
    def __init__(self):
        self._repo = LogRepository()

    def log(self, username, description, info="", suspicious=False):
        now = datetime.now()
        entry = {
            "date": now.strftime("%d-%m-%Y"),
            "time": now.strftime("%H:%M:%S"),
            "username": username or "-",
            "description": description,
            "info": info,
        }
        self._repo.add(entry, suspicious)

    def get_logs(self):
        return self._repo.get_all()

    def unread_suspicious_count(self):
        return self._repo.count_unread_suspicious()

    def mark_all_read(self):
        self._repo.mark_all_read()
