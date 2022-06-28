#include <boost/filesystem.hpp>
#include <json/json.h>
#include <test/TestCaseReader.h>
#include <test/libsolidity/util/SoltestTypes.h>
#include <test/libsolidity/util/TestFileParser.h>
#include <test/tools/expectations.h>

#include <cstdlib>
#include <iostream>

using namespace solidity::util;
using namespace solidity::frontend::test;

std::map<std::string, Builtin> makeBuiltins()
{
	return {
		{"isoltest_builtin_test",
		 [](FunctionCall const&) -> std::optional<solidity::bytes> {
			 return solidity::toBigEndian(solidity::u256(0x1234));
		 }},
		{"isoltest_side_effects_test",
		 [](FunctionCall const& _call) -> std::optional<solidity::bytes> {
			 if (_call.arguments.parameters.empty())
				 return solidity::toBigEndian(0);
			 else
				 return _call.arguments.rawBytes();
		 }},
		{"balance", [](FunctionCall const&) -> std::optional<solidity::bytes> { return solidity::toBigEndian(0); }},
		{"storageEmpty",
		 [](FunctionCall const&) -> std::optional<solidity::bytes> { return solidity::toBigEndian(0); }},
		{"account", [](FunctionCall const&) -> std::optional<solidity::bytes> { return solidity::toBigEndian(0); }},
	};
}

void printSemanticTests(std::string path)
{
	Json::Value callData{Json::objectValue};
	for (boost::filesystem::directory_entry& entry: boost::filesystem::recursive_directory_iterator(path))
	{
		std::size_t found = entry.path().string().find(".sol");
		if (found != std::string::npos)
		{
			Json::Value testData;
			TestCaseReader tcr = TestCaseReader(entry.path().string());
			std::vector<FunctionCall> calls
				= TestFileParser{tcr.stream(), makeBuiltins()}.parseFunctionCalls(tcr.lineNumber());
			for (auto const& call: calls)
			{
				Json::Value jsonFunc{Json::objectValue};
				FixedHash<4> hash(keccak256(call.signature));
				switch (call.kind)
				{
				case FunctionCall::Kind::Library:
				case FunctionCall::Kind::Builtin:
					continue;
				case FunctionCall::Kind::Regular:
					jsonFunc["callData"] = toHex(hash.asBytes() + call.arguments.rawBytes(), HexPrefix::Add);
					break;
				case FunctionCall::Kind::Constructor:
				case FunctionCall::Kind::LowLevel:
					jsonFunc["callData"] = toHex(call.arguments.rawBytes(), HexPrefix::Add);
				}

				jsonFunc["signature"] = call.signature;
				jsonFunc["expectations"] = toHex(call.expectations.rawBytes(), HexPrefix::Add);
				jsonFunc["failure"] = call.expectations.failure;

				testData.append(jsonFunc);
			}
			callData[entry.path().string()] = testData;
		}
	}
	std::cout << callData << std::endl;
}
