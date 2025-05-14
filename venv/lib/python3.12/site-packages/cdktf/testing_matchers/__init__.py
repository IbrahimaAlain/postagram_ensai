from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

import typeguard
from importlib.metadata import version as _metadata_package_version
TYPEGUARD_MAJOR_VERSION = int(_metadata_package_version('typeguard').split('.')[0])

def check_type(argname: str, value: object, expected_type: typing.Any) -> typing.Any:
    if TYPEGUARD_MAJOR_VERSION <= 2:
        return typeguard.check_type(argname=argname, value=value, expected_type=expected_type) # type:ignore
    else:
        if isinstance(value, jsii._reference_map.InterfaceDynamicProxy): # pyright: ignore [reportAttributeAccessIssue]
           pass
        else:
            if TYPEGUARD_MAJOR_VERSION == 3:
                typeguard.config.collection_check_strategy = typeguard.CollectionCheckStrategy.ALL_ITEMS # type:ignore
                typeguard.check_type(value=value, expected_type=expected_type) # type:ignore
            else:
                typeguard.check_type(value=value, expected_type=expected_type, collection_check_strategy=typeguard.CollectionCheckStrategy.ALL_ITEMS) # type:ignore

from .._jsii import *


class AssertionReturn(
    metaclass=jsii.JSIIMeta,
    jsii_type="cdktf.testingMatchers.AssertionReturn",
):
    '''(experimental) Class representing the contents of a return by an assertion.

    :stability: experimental
    '''

    def __init__(self, message: builtins.str, pass_: builtins.bool) -> None:
        '''(experimental) Create an AssertionReturn.

        :param message: - String message containing information about the result of the assertion.
        :param pass_: - Boolean pass denoting the success of the assertion.

        :stability: experimental
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6d7e2968390af0fb6be898c8ef2d45b03f3ce92f018160ff9c1b7b12b3730104)
            check_type(argname="argument message", value=message, expected_type=type_hints["message"])
            check_type(argname="argument pass_", value=pass_, expected_type=type_hints["pass_"])
        jsii.create(self.__class__, self, [message, pass_])

    @builtins.property
    @jsii.member(jsii_name="message")
    def message(self) -> builtins.str:
        '''(experimental) - String message containing information about the result of the assertion.

        :stability: experimental
        '''
        return typing.cast(builtins.str, jsii.get(self, "message"))

    @builtins.property
    @jsii.member(jsii_name="pass")
    def pass_(self) -> builtins.bool:
        '''(experimental) - Boolean pass denoting the success of the assertion.

        :stability: experimental
        '''
        return typing.cast(builtins.bool, jsii.get(self, "pass"))


@jsii.data_type(
    jsii_type="cdktf.testingMatchers.TerraformConstructor",
    jsii_struct_bases=[],
    name_mapping={"tf_resource_type": "tfResourceType"},
)
class TerraformConstructor:
    def __init__(self, *, tf_resource_type: builtins.str) -> None:
        '''
        :param tf_resource_type: 

        :stability: experimental
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d545ac86396aa3010111e8fc878f93f6922c9c83e011f1b15523627e8fbe21ef)
            check_type(argname="argument tf_resource_type", value=tf_resource_type, expected_type=type_hints["tf_resource_type"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "tf_resource_type": tf_resource_type,
        }

    @builtins.property
    def tf_resource_type(self) -> builtins.str:
        '''
        :stability: experimental
        '''
        result = self._values.get("tf_resource_type")
        assert result is not None, "Required property 'tf_resource_type' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TerraformConstructor(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AssertionReturn",
    "TerraformConstructor",
]

publication.publish()

def _typecheckingstub__6d7e2968390af0fb6be898c8ef2d45b03f3ce92f018160ff9c1b7b12b3730104(
    message: builtins.str,
    pass_: builtins.bool,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d545ac86396aa3010111e8fc878f93f6922c9c83e011f1b15523627e8fbe21ef(
    *,
    tf_resource_type: builtins.str,
) -> None:
    """Type checking stubs"""
    pass
