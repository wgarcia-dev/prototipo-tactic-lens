from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table, func, select

from backend.db import database_engine
from backend.safeguards import capacity


class SafeguardConcurrencyTests(unittest.TestCase):
    def test_two_transactions_cannot_claim_the_last_slot(self):
        engine = database_engine()
        self.addCleanup(engine.dispose)
        token = uuid4().hex
        tables = MetaData()
        config = Table(f"wip_{token}", tables, Column("tablero", Boolean, primary_key=True),
                       Column("wip_activo", Boolean), Column("limite_wip", Integer))
        task = Table(f"task_{token}", tables, Column("id_sesion", Integer, primary_key=True), Column("estado", String))
        session = Table(f"session_{token}", tables, Column("id_sesion", Integer, primary_key=True), Column("id_honeypot", Integer))
        with engine.begin() as conn:
            tables.create_all(conn)
            self.addCleanup(tables.drop_all, engine)
            conn.execute(config.insert().values(tablero=True, wip_activo=True, limite_wip=1))
            conn.execute(session.insert(), [{"id_sesion": i, "id_honeypot": 1} for i in (1, 2)])
            conn.execute(task.insert(), [{"id_sesion": i, "estado": "pendiente"} for i in (1, 2)])

        start = Barrier(2, timeout=5)

        def enter(session_id):
            try:
                with engine.begin() as conn:
                    conn.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
                    start.wait()
                    capacity(conn, {"salvaguarda_config": config, "salvaguarda": task, "sesion": session}, lock=True, require_space=True)
                    conn.execute(task.update().where(task.c.id_sesion == session_id).values(estado="en_desarrollo"))
            except HTTPException as error:
                return error.status_code
            return 200

        with patch("backend.safeguards.sensor_ids", return_value=(1,)), ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(enter, (1, 2)), [200, 409])
        with engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(task.c.estado, func.count()).group_by(task.c.estado)).all()),
                             {"pendiente": 1, "en_desarrollo": 1})
