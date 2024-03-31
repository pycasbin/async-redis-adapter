import json

import redis.asyncio as redis
from casbin import persist
from casbin.persist.adapters.asyncio import AsyncAdapter


class CasbinRule:
    """
    CasbinRule model
    """

    def __init__(
        self, ptype=None, v0=None, v1=None, v2=None, v3=None, v4=None, v5=None
    ):
        self.ptype = ptype
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5

    def dict(self):
        d = {"ptype": self.ptype}

        for value in dir(self):
            if (
                getattr(self, value) is not None
                and value.startswith("v")
                and value[1:].isnumeric()
            ):
                d[value] = getattr(self, value)

        return d

    def __str__(self):
        return ", ".join(self.dict().values())

    def __repr__(self):
        return '<CasbinRule :"{}">'.format(str(self))


class Adapter(AsyncAdapter):
    """the interface for Casbin adapters."""

    def __init__(
        self,
        host,
        port,
        db=0,
        username=None,
        password=None,
        key="casbin_rules",
        **kwargs,
    ):
        self.key = key
        self.client = redis.Redis(
            host=host,
            port=port,
            db=db,
            username=username,
            password=password,
            decode_responses=True,
            **kwargs,
        )

    async def drop_table(self):
        await self.client.delete(self.key)

    async def load_policy(self, model):
        """Implementing add Interface for casbin. Load all policy rules from redis

        Args:
            model (CasbinRule): CasbinRule object
        """

        length = await self.client.llen(self.key)
        for i in range(length):
            line = await self.client.lindex(self.key, i)
            line = json.loads(line)
            rule = CasbinRule(**line)
            persist.load_policy_line(str(rule), model)

    async def _save_policy_line(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        for index, value in enumerate(rule):
            setattr(line, f"v{index}", value)
        await self.client.rpush(self.key, json.dumps(line.dict()))

    async def _delete_policy_lines(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        for index, value in enumerate(rule):
            setattr(line, f"v{index}", value)

        # if rule is empty, do nothing
        # else find all given rules and delete them
        if len(line.dict()) == 0:
            return 0
        else:
            await self.client.lrem(self.key, 0, json.dumps(line.dict()))

    async def save_policy(self, model) -> bool:
        """Implement add Interface for casbin. Save the policy in redis

        Args:
            model (Class Model): Casbin Model which loads from .conf file usually.

        Returns:
            bool: True if succeed
        """
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    await self._save_policy_line(ptype, rule)
        return True

    async def add_policy(self, sec, ptype, rule):
        """Add policy rules to redis

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rule (CasbinRule): Casbin rule will be added

        Returns:
            bool: True if succeed else False
        """
        await self._save_policy_line(ptype, rule)
        return True

    async def add_policies(self, sec, ptype, rules):
        """AddPolicies adds policy rules to the storage.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rules: Casbin rules will be added

        Returns:
            bool: True if succeed else False
        """
        for rule in rules:
            await self.add_policy(sec, ptype, rule)
        return True

    async def remove_policy(self, sec, ptype, rule):
        """Remove policy rules in redis(rules duplicate will all be removed)

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rule (CasbinRule): Casbin rule if it is exactly same as will be removed.

        Returns:
            bool: True if succeed else False
        """
        await self._delete_policy_lines(ptype, rule)
        return True

    async def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the storage.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            rules: Casbin rules will be removed

        Returns:
            bool: True if succeed else False
        """
        for rule in rules:
            await self.remove_policy(sec, ptype, rule)
        return True

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """Remove policy rules that match the filter from the storage.
           This is part of the Auto-Save feature.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            field_index (int): The policy index at which the filed_values begins filtering. Its range is [0, 5]
            field_values(List[str]): A list of rules to filter policy which starts from

        Returns:
            bool: True if succeed else False
        """
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False

        length = await self.client.llen(self.key)
        for i in range(length):
            line = json.loads(await self.client.lindex(self.key, i))
            if ptype != line.get("ptype"):
                continue
            j = 1
            is_match = False
            keys = list(line.keys())[field_index : field_index + len(field_values) + 1]
            for field_value in field_values:
                if field_value == line[keys[j]]:
                    j += 1
                    if j == len(field_values):
                        is_match = True
                else:
                    break
            if is_match:
                await self.client.lset(self.key, i, "__CASBIN_DELETED__")

        await self.client.lrem(self.key, 0, "__CASBIN_DELETED__")
        return True

    async def update_policy(self, sec, ptype, old_rule, new_rule):
        """
        update_policy updates a policy rule from storage.
        This is part of the Auto-Save feature.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            old_rule: Casbin rule if it is exactly same as will be removed.
            new_rule: Casbin rule if it is exactly same as will be added.

        Returns:
            bool: True if succeed else False
        """
        old_rule_obj = CasbinRule(ptype=ptype)
        new_rule_obj = CasbinRule(ptype=ptype)
        for index, value in enumerate(old_rule):
            setattr(old_rule_obj, f"v{index}", value)
        for index, value in enumerate(new_rule):
            setattr(new_rule_obj, f"v{index}", value)

        # Convert old_rule_obj and new_rule_obj to json
        old_rule_json = json.dumps(old_rule_obj.dict())
        new_rule_json = json.dumps(new_rule_obj.dict())

        lua_script = """
            local old_rule_json = ARGV[1]
            local new_rule_json = ARGV[2]
            local rules = redis.call('lrange', KEYS[1], 0, -1)
            for i, rule_json in ipairs(rules) do
                local rule = cjson.decode(rule_json)
                if rule.ptype == ARGV[3] and rule_json == old_rule_json then
                    redis.call('lset', KEYS[1], i-1, new_rule_json)
                    return 1
                end
            end
            return 0
            """

        result = await self.client.eval(
            lua_script, 1, self.key, old_rule_json, new_rule_json, ptype
        )

        return result == 1

    async def update_policies(self, sec, ptype, old_rules, new_rules):
        """
        UpdatePolicies updates some policy rules to storage, like db, redis.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            old_rules: Casbin rule if it is exactly same as will be removed.
            new_rules: Casbin rule if it is exactly same as will be added.

        Returns:
            bool: True if succeed else False
        """
        for i in range(len(old_rules)):
            await self.update_policy(sec, ptype, old_rules[i], new_rules[i])
        return True

    async def update_filtered_policies(
        self, sec, ptype, new_rules, field_index, *field_values
    ):
        """
        update_filtered_policies deletes old rules and adds new rules.

        Args:
            sec (str): Section name, 'g' or 'p'
            ptype (str): Policy type, 'g', 'g2', 'p', etc.
            new_rules: Casbin rule if it is exactly same as will be added.
            field_index (int): The policy index at which the filed_values begins filtering. Its range is [0, 5]
            field_values(List[str]): A list of rules to filter policy which starts from

        Returns:
            bool: True if succeed else False
        """
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False

        await self.remove_filtered_policy(sec, ptype, field_index, *field_values)
        await self.add_policies(sec, ptype, new_rules)
        return True
