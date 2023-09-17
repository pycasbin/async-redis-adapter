Async Redis Adapter for PyCasbin
====

[![GitHub Actions](https://github.com/pycasbin/async-redis-adapter/workflows/build/badge.svg?branch=master)](https://github.com/pycasbin/async-redis-adapter/actions)
[![Coverage Status](https://coveralls.io/repos/github/pycasbin/async-redis-adapter/badge.svg?branch=master)](https://coveralls.io/github/pycasbin/async-redis-adapter?branch=master)
[![Version](https://img.shields.io/pypi/v/casbin_async_redis_adapter.svg)](https://pypi.org/project/casbin_async_redis_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_async_redis_adapter.svg)](https://pypi.org/project/casbin_async_redis_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_async_redis_adapter.svg)](https://pypi.org/project/casbin_async_redis_adapter/)
[![Download](https://img.shields.io/pypi/dm/casbin_async_redis_adapter.svg)](https://pypi.org/project/casbin_async_redis_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_async_redis_adapter.svg)](https://pypi.org/project/casbin_async_redis_adapter/)

Async Redis Adapter is the async [redis](https://redis.io/) adapter for [PyCasbin](https://github.com/casbin/pycasbin).
With this
library, Casbin can load policy from redis or save policy to it.

## Installation

```
pip install casbin_async_redis_adapter
```

## Simple Example

```python
import asyncio
from casbin_async_redis_adapter import Adapter
import casbin


async def get_enforcer():
    adapter = Adapter("localhost", 6379, encoding="utf-8")
    e = casbin.AsyncEnforcer("rbac_model.conf", adapter)
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

    e = casbin.AsyncEnforcer("rbac_model.conf", adapter)
    await e.load_policy()

    return e


sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.


async def main():
    e = await get_enforcer()
    if e.enforce("alice", "data1", "read"):
        print("alice can read data1")
    else:
        print("alice can not read data1")


asyncio.run(main())
```

## Configuration

`Adapter()` enable decode_responses by default and supports any Redis parameter configuration.

To use casbin_redis_adapter, you must provide the following parameter configuration

- `host`: address of the redis service
- `port`: redis service port

The following parameters are provided by default

- `db`: redis database, default is `0`
- `username`: redis username, default is `None`
- `password`: redis password, default is `None`
- `key`: casbin rule to store key, default is `casbin_rules`

For more parameters, please follow [redis-py](https://redis.readthedocs.io/en/stable/connections.html#redis.Redis)

### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).