--
-- Sentinel: Sentry.io for Defold.
-- *******************************
--
-- The latest version available at: https://github.com/indiesoftby/defold-sentinel
-- SDK Development Documentation: https://develop.sentry.dev/sdk/overview/
--

local M = {}

local LOG_PREFIX = "SENTINEL: "
local LOGGER_NAME = "sentinel"
local VERSION = "1.2.0"
local USER_AGENT = "sentinel-sentry/" .. VERSION

local APP_PATH = sys.get_application_path()
local ENGINE_INFO = sys.get_engine_info()
local SYS_INFO = sys.get_sys_info()

--- Generates a unique event ID suitable for use in Sentry.
-- This function creates a 32-character hexadecimal string based on the current time and random numbers.
-- @treturn string A 32-character hexadecimal string representing the event ID.
local function generate_event_id()
    local h = hash_to_hex(hash(tostring(socket.gettime()) .. string.format("%07x", math.random(0, 0xfffffff))))
    while string.len(h) < 32 do
        h = h .. hash_to_hex(hash(string.format("%07x", math.random(0, 0xfffffff))))
    end
    return string.sub(h, 1, 32)
end

--- Logs a message via `print`. If running in HTML5 and not in debug mode, it uses `console.log`.
-- @tparam any v The value to be logged.
local function log_print(v)
    if html5 and not ENGINE_INFO.is_debug then
        html5.run("console.log(" .. json.encode(LOG_PREFIX .. tostring(v)) .. ")")
    else
        print(LOG_PREFIX .. tostring(v))
    end
end

--- Merges key-value pairs from `src` table into `dest`. Copies non-empty string values from src to dest.
-- @tparam table dest The destination table to merge into.
-- @tparam table src The source table to merge from if not nil.
local function merge_kv(dest, src)
    if src then
        for k, v in pairs(src) do
            local s = tostring(v)
            if string.len(s) > 0 then
                dest[k] = s
            end
        end
    end
end

--- This function helps to throttle the amount of messages your game is sending to not spam Sentry servers.
-- Default rate limit: 10 messages per 300 seconds.
-- @tparam table transactions A table containing transaction entries
-- @treturn boolean Returns true if the transaction was added, false if throttled
local function add_transaction(transactions)
    table.insert(transactions, { time = socket.gettime() })

    if #transactions > 10 then
        local time = transactions[1].time

        if time > socket.gettime() - 300 then
            -- Throttle!
            table.remove(transactions) -- pop
            return false
        else
            table.remove(transactions, 1) -- shift
        end
    end

    return true
end

--- Parses a host and port from a given host string.
-- @tparam string protocol The protocol being used (e.g., 'http' or 'https')
-- @tparam string host The host string, which may include a port number
-- @treturn string|nil The parsed host name, or nil if parsing fails
-- @treturn number|nil The parsed port number, or nil if parsing fails
-- @treturn string|nil An error message if parsing fails, or nil on success
local function parse_host_port(protocol, host)
    local i = string.find(host, ":")
    if not i then
        return host, protocol == 'https' and 443 or 80
    end

    local port_str = string.sub(host, i + 1)
    local port = tonumber(port_str)
    if not port then
        return nil, nil, "illegal port: " .. port_str
    end

    return string.sub(host, 1, i - 1), port
end

--- Parses DSN string
-- @tparam string dsn The DSN string to parse
-- @tparam[opt] table obj The table to store the parsed DSN fields
-- @treturn table|nil The parsed DSN table, or nil if parsing fails
-- @treturn string|nil An error message if parsing fails, or nil on success 
local function parse_dsn(dsn, obj)
    if not obj then
        obj = {}
    end
    assert(type(obj) == "table")

    -- '{PROTOCOL}://{PUBLIC_KEY}@{HOST}/{PATH}{PROJECT_ID}'
    obj.protocol, obj.public_key, obj.long_host, obj.path, obj.project_id =
        string.match(dsn, "^([^:]+)://([^@]+)@([^/]+)(.*/)(.+)$")

    if obj.protocol and obj.public_key and obj.long_host and obj.project_id then
        local host, port, err = parse_host_port(obj.protocol, obj.long_host)

        if not host then
            return nil, err
        end

        obj.host = host
        obj.port = port

        obj.request_uri = string.format("%sapi/%s/store/", obj.path, obj.project_id)
        obj.server = string.format("%s://%s:%d%s", obj.protocol, obj.host, obj.port, obj.request_uri)

        return obj
    end

    return nil, "failed to parse DSN string"
end

--- Generates a callback function for handling Sentry API responses
-- @tparam function|nil next The optional callback function to be called after processing the response
-- @treturn function The generated callback function
-- @usage local callback = request_callback(function(id, err) print(id, err) end)
local function request_callback(next)
    return function(self, id, resp)
        if resp.status == 200 then
            local ok, retval = pcall(json.decode, resp.response)
            if ok then
                -- valid response
                if next then
                    next(retval.id, nil)
                end
            else
                -- error
                if next then
                    next(nil, "Decode error: " .. retval)
                end
            end
        else
            if M.config.debug then
                log_print("Invalid request, response status " .. resp.status)
            end
            if next then
                next(nil, "Response status " .. resp.status)
            end
        end
    end
end

--- Creates a new event structure for Sentry reporting.
-- https://develop.sentry.dev/sdk/event-payloads/
-- @treturn table A new event table with initialized fields
local function new_event()
    local event = {}
    event.event_id = generate_event_id()
    event.timestamp = socket.gettime()
    -- 'javascript' says Sentry server to catch user IP from request. TODO: ask Sentry devs about this issue.
    event.platform = "javascript" -- important!
    event.logger = LOGGER_NAME

    event.release = M.config.release
    event.dist = M.config.dist
    event.environment = M.config.environment
    event.user = M.config.user

    event.tags = {}
    event.extra = {}

    if string.len(APP_PATH) > 0 then
        event.tags["application_path"] = APP_PATH
    end

    for k, v in pairs(ENGINE_INFO) do
        local s = tostring(v)
        if string.len(s) > 0 then
            event.tags["engine_info." .. k] = s
        end
    end

    for k, v in pairs(SYS_INFO) do
        local s = tostring(v)
        if string.len(s) > 0 then
            event.tags["sys_info." .. k] = s
        end
    end

    event.tags["project.version"] = sys.get_config("project.version")

    if html5 then
        event.request = {
            url = html5.run("window.location.href"),
            headers = {
                ["User-Agent"] = html5.run("window.navigator.userAgent")
            }
        }
    else
        event.contexts = {
            os = {
                name = SYS_INFO.system_name
            }
        }
    end

    return event
end

--- Sends the JSON-encoded event data to the Sentry server.
-- @tparam string json_str The JSON-encoded event data to send.
-- @tparam[opt] function callback A callback function to be called after the request is completed.
local function send(json_str, callback)
    local url = M.obj.server .. "?sentry_version=7&sentry_key=" .. M.obj.public_key
    local method = "POST"
    local headers = {["Content-Type"] = "application/json"}
    if not html5 then
        headers["User-Agent"] = USER_AGENT
    end
    local post_data = json_str
    local options = {
        timeout = M.config.send_timeout
    }

    local cb_handler = request_callback(callback)
    if M.config.dry_run then
        if M.config.debug then
            log_print("Sending http request (dry run)")
        end
        cb_handler(M.obj, "(dry run)", {response = json.encode({id = "(dry run)"}), status = 200})
    else
        http.request(url, method, cb_handler, headers, post_data, options)
    end
end

local function error_handler(source, message, traceback)
    local error = {source = source, message = message, traceback = traceback}
    local pstatus, perr = pcall(M.capture_exception, error)
    if not pstatus then
        log_print("Exception capture error " .. perr)
    end

    if M.config.on_soft_crash then
        pstatus, perr = pcall(M.config.on_soft_crash, error)
        log_print("Soft crash callback error " .. perr)
    end
end

---
--- PUBLIC API
---

--- Initialize Sentinel's Sentry Client.
-- Configuration should happen as early as possible in your application's lifecycle.
-- @tparam table config Configuration table
-- @tparam string config.dsn The DSN tells the SDK where to send the events
-- @tparam[opt=false] boolean config.debug Turn on to debug and check what data Sentinel sends
-- @tparam[opt=false] boolean config.dry_run If true, don't actually send data to Sentry
-- @tparam[opt=false] boolean config.gameanalytics Whether to duplicate errors to GameAnalytics if it's installed
-- @tparam[opt=30] number config.send_timeout HTTP request timeout
-- @tparam[opt=true] boolean config.set_error_handler Install a custom Lua error handler
-- @tparam[opt=true] boolean config.load_previous_crash Load the previous crash dump if it exists
-- @tparam[opt] table config.extra Extra data to send with every event
-- @tparam[opt] table config.tags Tags to send with every event
-- @tparam[opt] function config.on_soft_crash Callback function for soft crashes
-- @tparam[opt] function config.on_hard_crash Callback function for hard crashes
-- @tparam[opt] string config.release Project's Release ID
-- @tparam[opt] string config.dist The distribution. Used to disambiguate build or deployment variants
-- @tparam[opt] string config.environment The environment. This string is freeform. E.g., 'staging' vs 'prod'
-- @tparam[opt] table config.user User information to include with events
function M.init(config)
    assert(type(config) == "table", "`config` should be a table.")
    M.config = config

    assert(type(M.config.dsn) == "string", "`config.dsn` is required and should be a string.")

    -- Default settings
    if type(M.config.send_timeout) ~= "number" then
        M.config.send_timeout = 30 -- seconds
    end
    if type(M.config.set_error_handler) ~= "boolean" then
        M.config.set_error_handler = true
    end
    if type(M.config.load_previous_crash) ~= "boolean" then
        M.config.load_previous_crash = true
    end

    --
    local err
    M.obj, err = parse_dsn(M.config.dsn)
    assert(err == nil, "Invalid the DSN url.")

    M.transactions = {}

    M.config.extra = M.config.extra or {}
    M.config.tags = M.config.tags or {}

    if M.config.set_error_handler then
        sys.set_error_handler(error_handler)
    end

    if M.config.debug then
        log_print(USER_AGENT .. ", init OK")
    end

    if not M.config.load_previous_crash then return end

    local handle = crash.load_previous()
    if handle then
        if M.config.debug then
            log_print("Submitting previous crash dump")
        end

        local _, extra_data = pcall(crash.get_extra_data, handle)
        local _, backtrace = pcall(crash.get_backtrace, handle)

        local error = {
            source = "crash",
            message = json.encode(extra_data),
            traceback = json.encode(backtrace),
            fatal = true
        }
        local pstatus, perr = pcall(M.capture_exception, error)
        if not pstatus then
            log_print("Crash capture error " .. perr)
        end

        if M.config.on_hard_crash then
            pstatus, perr = pcall(M.config.on_hard_crash, error)
            log_print("Hard crash callback error " .. perr)
        end

        pcall(crash.release, handle)
    end
end

--- Manually adds a breadcrumb whenever something interesting happens.
-- Sentry uses breadcrumbs to create a trail of events that happened prior to an issue.
-- These events are very similar to traditional logs, but can record more rich structured data.
-- - https://docs.sentry.io/platforms/javascript/guides/vue/enriching-events/breadcrumbs/
-- - https://docs.sentry.io/development/sdk-dev/event-payloads/breadcrumbs/
-- @tparam table breadcrumb A table containing breadcrumb information
-- @tparam string breadcrumb.category The category of the breadcrumb
-- @tparam string breadcrumb.message The message content of the breadcrumb
-- @usage sentry.add_breadcrumb({ category = "log", message = "Test breadcrumb message" })
function M.add_breadcrumb(breadcrumb)
    if type(M.config) ~= "table" then
        return
    end

    if M.breadcrumbs == nil then
        M.breadcrumbs = {}
    end

    if type(breadcrumb) ~= "table" then
        breadcrumb = {}
    end
    breadcrumb.timestamp = socket.gettime()

    table.insert(M.breadcrumbs, breadcrumb)
    if #M.breadcrumbs > 10 then
        table.remove(M.breadcrumbs, 1)
    end
end

--- Set a globally defined tag.
-- This function allows you to set a tag that will be included in all future error reports or messages.
-- @tparam string key The key for the tag.
-- @tparam string|number|boolean value The value.
-- @usage sentry.set_tag("environment", "production")
-- @usage sentry.set_tag("user_id", 12345)
function M.set_tag(key, value)
    if type(M.config) ~= "table" then
        return
    end

    M.config.tags[key] = value
end

--- Sets globally defined extra data.
-- This function allows you to set extra data that will be included in all future error reports or messages.
-- @tparam string key The key for the extra data.
-- @tparam string|number|boolean value The value.
-- @usage sentry.set_extra("user_level", 42)
-- @usage sentry.set_extra("last_checkpoint", "boss_room")
function M.set_extra(key, value)
    if type(M.config) ~= "table" then
        return
    end

    M.config.extra[key] = value
end

--- Capture an error, i.e. send data to Sentry about the error.
-- If you set a global error handler, then you don't need to call this function.
-- @tparam table err Error information
-- @tparam string err.message Error message
-- @tparam[opt] string err.traceback Error traceback
-- @tparam[opt] string err.source Error source
-- @tparam[opt] boolean err.fatal Whether the error is fatal
-- @tparam[opt] table err.tags Additional tags to include
-- @tparam[opt] table err.extra Additional extra data to include  
-- @tparam[opt] function err.callback A function to be called after the message is sent, with parameters (id, err_str)
-- @usage
-- local err = {
--     message = "Division by zero",
--     traceback = debug.traceback(),
--     source = "math_operations.lua",
--     fatal = false,
--     tags = {level = "boss"},
--     extra = {input_value = 0},
--     callback = function(id, err_str) 
--         if id then
--             print("Captured with ID: " .. tostring(id))
--         else
--             print("Failed to capture error: " .. err_str)
--         end
--     end
-- }
-- sentry.capture_exception(err)
function M.capture_exception(err)
    assert(type(M.config) == "table", "initialize first")
    assert(type(err) == "table", "`capture_exception` expects a table.")

    if not add_transaction(M.transactions) then
        if err.callback then
            err.callback(nil, "Too much messages per minute.")
        else
            log_print("Dropping the message, too much messages per minute.")
        end
        return
    end

    if M.config.gameanalytics and gameanalytics then
        gameanalytics.addErrorEvent({
            severity = err.fatal and "Critical" or "Error",
            message = (err.message or "Error") .. "\n" .. err.traceback
        })
    end

    local event = new_event()

    if err.fatal then
        event.level = "fatal"
    else
        event.level = "error"
    end

    event.exception = {}
    event.exception["type"] = err.message or "error"
    event.exception["value"] = err.traceback

    event.tags["source"] = err.source

    merge_kv(event.tags, M.config.tags)
    merge_kv(event.extra, M.config.extra)

    merge_kv(event.tags, err.tags)
    merge_kv(event.extra, err.extra)

    if M.breadcrumbs then
        event.breadcrumbs = M.breadcrumbs
    end

    if next(event.extra) == nil then
        event.extra = nil
    end

    local json_str = json.encode(event)
    if M.config.debug then
        log_print("JSON payload " .. json_str)
    end
    send(json_str, function(id, err_str)
        if id and M.config.debug then
            log_print("Exception is recorded as " .. id)
        end

        if err.callback then
            err.callback(id, err_str)
        end
    end)
end

--- Captures a bare message to be sent to Sentry.
-- @tparam table msg A table containing message details
-- @tparam string msg.message The textual content of the message
-- @tparam[opt="info"] string msg.level The severity level of the message. Can be "fatal", "error", "warning", "info", or "debug"
-- @tparam[opt] table msg.tags Additional tags to include
-- @tparam[opt] table msg.extra Additional extra data to include
-- @tparam[opt] function msg.callback A function to be called after the message is sent, with parameters (id, err_str)
-- @usage
-- sentry.capture_message({
--     message = "User performed action X",
--     level = "info",
--     tags = {group = "newbie"},
--     extra = {user_id = "12345", inventory = "sword, shield, potion"},
--     callback = function(id, err) print(id, err) end
-- })
function M.capture_message(msg)
    assert(type(M.config) == "table", "initialize first")
    assert(type(msg) == "table", "`capture_message` expects a table.")

    if not add_transaction(M.transactions) then
        if msg.callback then
            msg.callback(nil, "Too much messages per minute.")
        else
            log_print("Dropping the message, too much messages per minute.")
        end
        return
    end

    local event = new_event()

    event.message = msg.message or "N/A"
    event.level = msg.level or "info"

    merge_kv(event.tags, M.config.tags)
    merge_kv(event.extra, M.config.extra)

    merge_kv(event.tags, msg.tags)
    merge_kv(event.extra, msg.extra)

    if M.breadcrumbs then
        event.breadcrumbs = M.breadcrumbs
    end

    if next(event.extra) == nil then
        event.extra = nil
    end

    local json_str = json.encode(event)
    if M.config.debug then
        log_print("JSON payload " .. json_str)
    end
    send(json_str, function(id, err_str)
        if id and M.config.debug then
            log_print("Message is recorded as " .. id)
        end

        if msg.callback then
            msg.callback(id, err_str)
        end
    end)
end

return M
