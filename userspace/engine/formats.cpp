/*
Copyright (C) 2020 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <json/json.h>

#include "formats.h"
#include "falco_engine.h"
#include "banned.h" // This raises a compilation error when certain functions are used

const static struct luaL_Reg ll_falco[] =
	{
		{"is_format_valid", &falco_formats_lua::is_format_valid},
		{NULL, NULL}};

void falco_formats_lua::init(lua_State *ls)
{
	luaL_openlib(ls, "formats", ll_falco, 0);
}

int falco_formats_lua::is_format_valid(lua_State *ls)
{

	if (! lua_islightuserdata(ls, -3) ||
	    ! lua_isstring(ls, -2) ||
	    ! lua_isstring(ls, -1))
	{
		lua_pushstring(ls, "Invalid arguments passed to is_format_valid");
		lua_error(ls);
	}

	falco_engine *engine = (falco_engine *) lua_topointer(ls, -3);
	string source = luaL_checkstring(ls, -2);
	string format = luaL_checkstring(ls, -1);

	try
	{
		std::shared_ptr<gen_event_formatter> formatter;

		formatter = engine->create_formatter(source, format);

		// Don't need to return anything--if the formatter was
		// created without an exception that's success.
		lua_pushnil(ls);
	}
	catch(exception &e)
	{
		std::ostringstream os;

		os << "Invalid output format '"
		   << format
		   << "': '"
		   << e.what()
		   << "'";

		lua_pushstring(ls, os.str().c_str());
	}

	return 1;
}

falco_formats::falco_formats(falco_engine *engine,
			     bool json_include_output_property)
	: m_falco_engine(engine),
	  m_json_include_output_property(json_include_output_property)
{
}

falco_formats::~falco_formats()
{
}

string falco_formats::format_event(gen_event *evt, const std::string &rule, const std::string &source,
				   const std::string &level, const std::string &format)
{
	string line;

	std::shared_ptr<gen_event_formatter> formatter;

	formatter = m_falco_engine->create_formatter(source, format);

	// Format the original output string, regardless of output format
	formatter->tostring_withformat(evt, line, gen_event_formatter::OF_NORMAL);

	if(formatter->get_output_format() == gen_event_formatter::OF_JSON)
	{
		string json_line;

		// Format the event into a json object with all fields resolved
		formatter->tostring(evt, json_line);

		// The formatted string might have a leading newline. If it does, remove it.
		if(json_line[0] == '\n')
		{
			json_line.erase(0, 1);
		}

		// For JSON output, the formatter returned a json-as-text
		// object containing all the fields in the original format
		// message as well as the event time in ns. Use this to build
		// a more detailed object containing the event time, rule,
		// severity, full output, and fields.
		Json::Value event;
		Json::FastWriter writer;
		string full_line;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = evt->get_ts() / 1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];  // sizeof ".sssssssssZ"
		string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", evt->get_ts() % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;
		event["time"] = iso8601evttime;
		event["rule"] = rule;
		event["priority"] = level;

		if(m_json_include_output_property)
		{
			// This is the filled-in output line.
			event["output"] = line;
		}

		full_line = writer.write(event);

		// Json::FastWriter may add a trailing newline. If it
		// does, remove it.
		if(full_line[full_line.length() - 1] == '\n')
		{
			full_line.resize(full_line.length() - 1);
		}

		// Cheat-graft the output from the formatter into this
		// string. Avoids an unnecessary json parse just to
		// merge the formatted fields at the object level.
		full_line.pop_back();
		full_line.append(", \"output_fields\": ");
		full_line.append(json_line);
		full_line.append("}");
		line = full_line;
	}

	return line.c_str();
}

map<string, string> falco_formats::get_field_values(gen_event *evt, const std::string &source,
						    const std::string &format)
{
	std::shared_ptr<gen_event_formatter> formatter;

	formatter = m_falco_engine->create_formatter(source, format);

	map<string, string> ret;

	if (! formatter->get_field_values(evt, ret))
	{
		throw falco_exception("Could not extract all field values from event");
	}

	return ret;
}
