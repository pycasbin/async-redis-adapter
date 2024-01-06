from casbin_async_redis_adapter.adapter import Adapter, CasbinRule

from unittest import IsolatedAsyncioTestCase
import redis
import casbin
import os


def get_fixture(path):
    """
    get model path
    """
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


async def get_enforcer():
    adapter = Adapter("localhost", 6379, encoding="utf-8")
    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    model = e.get_model()

    model.clear_policy()
    model.add_policy("p", "p", ["alice", "data1", "read"])
    await adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["bob", "data2", "write"])
    await adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "read"])
    await adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("p", "p", ["data2_admin", "data2", "write"])
    await adapter.save_policy(model)

    model.clear_policy()
    model.add_policy("g", "g", ["alice", "data2_admin"])
    await adapter.save_policy(model)

    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    await e.load_policy()

    return e


def clear_db(dbname):
    client = redis.Redis()
    client.delete(dbname)


class TestConfig(IsolatedAsyncioTestCase):
    """
    unittest
    """

    def setUp(self):
        clear_db("casbin_rules")

    def tearDown(self):
        clear_db("casbin_rules")

    async def test_enforcer_basic(self):
        """
        test policy
        """
        e = await get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_add_policy(self):
        """
        test add_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test add_policy after insert 2 rules
        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        await adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_add_policies(self):
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test add_policy after insert rules
        await adapter.add_policies(
            sec="p",
            ptype="p",
            rules=(("alice", "data1", "write"), ("bob", "data2", "read")),
        )

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_remove_policy(self):
        """
        test remove_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy after delete a role definition
        result = await adapter.remove_policy(
            sec="g", ptype="g", rule=("alice", "data2_admin")
        )

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(result)

    async def test_remove_policies(self):
        """
        test remove_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy after delete a role definition
        result = await adapter.remove_policies(
            sec="p",
            ptype="p",
            rules=(("data2_admin", "data2", "read"), ("data2_admin", "data2", "write")),
        )

        # reload policies from database
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(result)

    async def test_remove_policy_no_remove_when_rule_is_incomplete(self):
        adapter = Adapter("localhost", 6379)
        e = casbin.AsyncEnforcer(get_fixture("rbac_with_resources_roles.conf"), adapter)

        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "write"))
        await adapter.add_policy(sec="p", ptype="p", rule=("alice", "data1", "read"))
        await adapter.add_policy(sec="p", ptype="p", rule=("bob", "data2", "read"))
        await adapter.add_policy(
            sec="p", ptype="p", rule=("data_group_admin", "data_group", "write")
        )
        await adapter.add_policy(sec="g", ptype="g", rule=("alice", "data_group_admin"))
        await adapter.add_policy(sec="g", ptype="g2", rule=("data2", "data_group"))

        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        # test remove_policy doesn't remove when given an incomplete policy
        await adapter.remove_policy(sec="p", ptype="p", rule=("alice", "data1"))
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_save_policy(self):
        """
        test save_policy
        """

        e = await get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ("alice", "data4", "read"))

        adapter = e.get_adapter()
        await adapter.save_policy(model)

        self.assertTrue(e.enforce("alice", "data4", "read"))

    async def test_remove_filtered_policy(self):
        """
        test remove_filtered_policy
        """
        e = await get_enforcer()
        adapter = e.get_adapter()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        result = await adapter.remove_filtered_policy(
            "g", "g", 6, "alice", "data2_admin"
        )
        await e.load_policy()
        self.assertFalse(result)

        result = await adapter.remove_filtered_policy(
            "g", "g", 0, *[f"v{i}" for i in range(7)]
        )
        await e.load_policy()
        self.assertFalse(result)

        result = await adapter.remove_filtered_policy(
            "g", "g", 0, "alice", "data2_admin"
        )
        await e.load_policy()
        self.assertTrue(result)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_str(self):
        """
        test __str__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(rule.__str__(), "p, alice, data1, read")

    def test_dict(self):
        """
        test dict function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(
            rule.dict(), {"ptype": "p", "v0": "alice", "v1": "data1", "v2": "read"}
        )

    def test_repr(self):
        """
        test __repr__ function
        """
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule :"p, alice, data1, read">')
