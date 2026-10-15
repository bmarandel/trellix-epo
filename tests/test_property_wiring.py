"""
Regression test for the property(getter, setter) wiring bug found in
trellix_epo/ta/general.py this session: six properties had their
setter argument accidentally duplicated as the getter, or swapped, e.g.
`log_roll_over = property(get_log_roll_over, get_log_roll_over)`. This walks
every class defined in the package and asserts no property's setter is
literally the same function object as its getter.

A genuinely read-only property (fset is None, e.g. test_cert_authentication)
is not a violation and must not be flagged.
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


def test_no_property_has_setter_equal_to_getter():
    violations = []
    for cls in _iter_package_classes():
        for attr_name, attr in vars(cls).items():
            if isinstance(attr, property) and attr.fset is not None:
                if attr.fset is attr.fget:
                    violations.append(f"{cls.__module__}.{cls.__qualname__}.{attr_name}")
    assert not violations, (
        "Found propert(y/ies) whose setter is the same function as its getter "
        f"(read-only or a copy/paste bug): {violations}"
    )
