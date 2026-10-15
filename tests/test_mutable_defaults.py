"""
Regression test for the mutable-default-argument bug found in this session:
ExclusionList, OASProcessList, OASURLList and ODSLocationList all used to
declare `def __init__(self, x=list())`, so every instance created without an
explicit argument shared and mutated the same list object. This walks every
class defined in the package and asserts no __init__ parameter defaults to
a mutable list/dict/set instance.
"""

import importlib
import inspect
import pkgutil

import trellix_epo


def _iter_package_classes():
    seen = set()
    package = trellix_epo
    for module_info in pkgutil.walk_packages(package.__path__, prefix=package.__name__ + '.'):
        module = importlib.import_module(module_info.name)
        for name, obj in vars(module).items():
            if inspect.isclass(obj) and obj.__module__ == module.__name__ and obj not in seen:
                seen.add(obj)
                yield obj


def test_no_init_has_mutable_default_argument():
    violations = []
    for cls in _iter_package_classes():
        if '__init__' not in vars(cls):
            continue
        signature = inspect.signature(cls.__init__)
        for param in signature.parameters.values():
            if isinstance(param.default, (list, dict, set)):
                violations.append(
                    f"{cls.__module__}.{cls.__qualname__}.__init__(..., "
                    f"{param.name}={param.default!r})"
                )
    assert not violations, (
        f"Found __init__ parameter(s) with a mutable default argument: {violations}"
    )
