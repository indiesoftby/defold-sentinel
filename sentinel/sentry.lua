--
-- Sentinel: Sentry.io for Defold.
-- *******************************
--
-- The latest version available at: https://github.com/indiesoftby/defold-sentinel
-- SDK Development Documentation: https://develop.sentry.dev/sdk/overview/
--

local rxi_json = require("sentinel.json")

local M = {}

local LOG_PREFIX = "SENTINEL: "
local LOGGER_NAME = "sentinel"
local VERSION = "1.0.0"
local USER_AGENT = "sentinel-sentry/" .. VERSION

local APP_PATH = sys.get_application_path()
local ENGINE_INFO = sys.get_engine_info()
local SYS_INFO = sys.get_sys_info()

-- Returns a string suitable to be used as `event_id`.
local function generate_event_id()
    local h = hash_to_hex(hash(tostring(socket.gettime()) .. string.format("%07x", math.random(0, 0xfffffff))))
    while string.len(h) < 32 do
        h = h .. hash_to_hex(hash(string.format("%07x", math.random(0, 0xfffffff))))
    end
    return string.sub(h, 1, 32)
end

local function log_print(v)
    if html5 and not ENGINE_INFO.is_debug then
        html5.run("console.log(" .. rxi_json.encode(LOG_PREFIX .. tostring(v)) .. ")")
    else
        print(LOG_PREFIX .. tostring(v))
    end
end

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

--- This function helps to throttle the amount of messages your game
-- is sending to not spam Sentry servers.
-- Default rate limit: 10 messages per 300 seconds.
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

--- Parsed DSN table containing its different fields.
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

local function request_callback(next)
    return function(self, id, resp)
        if resp.status == 200 then
            local ok, retval = pcall(rxi_json.decode, resp.response)
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
                log_print("Invalid request")
            end
            if next then
                next(nil, "Response status " .. resp.status)
            end
        end
    end
end

-- https://docs.sentry.io/development/sdk-dev/event-payloads/
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
        local webgl_renderer = html5.run("Module['__debugInfoWebGLRenderer']")
        if webgl_renderer and webgl_renderer ~= "undefined" then
            event.tags["gl_info.renderer"] = webgl_renderer
        end

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
        cb_handler(M.obj, "(dry run)", {response = rxi_json.encode({id = "(dry run)"}), status = 200})
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
-- @param config table = { 
--          dsn = string, -- REQUIRED
--          -- OPTIONAL:
--          -- Turn on to debug and check what data Sentinel sends:
--          debug = boolean,
--          dry_run = boolean,
--          -- Options
--          gameanalytics = boolean, -- Default: false
--          send_timeout = number, -- Default: 30 (seconds)
--          set_error_handler = boolean, -- Default: true
--          load_previous_crash = boolean, -- Default: true
--          -- Extra/tags data
--          extra = {},
--          tags = {},
--          -- Callbacks
--          on_soft_crash = function,
--          on_hard_crash = function,
--          -- Sentry-specific things that Sentinel sends with every captured message/error:
--          release = string, -- Project's Release ID
--          dist = string, -- The distribution. Distributions are used to disambiguate build or deployment variants.
--          environment = string, -- The environment. This string is freeform. Think `staging` vs `prod` or similar.
--          user = table,
--      }
function M.init(config)
    assert(type(config) == "table", "`config` should be a table.")
    M.config = config

    assert(M.config.dsn, "`dsn` is required.")

    -- Default settings
    M.config.send_timeout = M.config.send_timeout or 30 -- seconds
    M.config.set_error_handler = M.config.set_error_handler or true
    M.config.load_previous_crash = M.config.load_previous_crash or true

    --
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
            message = rxi_json.encode(extra_data),
            traceback = rxi_json.encode(backtrace),
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

--- Manually add a breadcrumb whenever something interesting happens.
-- Sentry uses breadcrumbs to create a trail of events that happened prior to an issue.
-- These events are very similar to traditional logs, but can record more rich structured data.
-- - https://docs.sentry.io/platforms/javascript/guides/vue/enriching-events/breadcrumbs/
-- - https://docs.sentry.io/development/sdk-dev/event-payloads/breadcrumbs/
-- Example: sentry.add_breadcrumb({ category = "log", message = "Test breadcrumb message" })
-- @param breadcrumb table = { category, message }
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
-- @param key string
-- @param value string|number|boolean
function M.set_tag(key, value)
    if type(M.config) ~= "table" then
        return
    end

    M.config.tags[key] = value
end

--- Set globally defined extra data.
-- @param key string
-- @param value string|number|boolean
function M.set_extra(key, value)
    if type(M.config) ~= "table" then
        return
    end

    M.config.extra[key] = value
end

--- Capture an error, i.e. send data to Sentry about the error.
-- @param err table = { message, traceback, source, fatal, tags, extra, callback }
function M.capture_exception(err)
    assert(type(M.config) == "table", "initialize first")
    assert(type(err) == "table", "`capture_exception` expects a table.")

    if not add_transaction(M.transactions) then
        if msg.callback then
            msg.callback(nil, "Too much messages per minute.")
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

    local json_str = rxi_json.encode(event)
    if M.config.debug then
        log_print("JSON payload " .. json_str)
    end
    send(json_str, function(id, err)
        if id and M.config.debug then
            log_print("Exception is recorded as " .. id)
        end

        if msg.callback then
            msg.callback(id, err)
        end
    end)
end

--- Capture a bare message. A message is textual information that should be sent to Sentry.
-- Level can be "fatal", "error", "warning", "info", and "debug"
-- @param msg table = { message, level, tags, extra, callback }
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

    local json_str = rxi_json.encode(event)
    if M.config.debug then
        log_print("JSON payload " .. json_str)
    end
    send(json_str, function(id, err)
        if id and M.config.debug then
            log_print("Message is recorded as " .. id)
        end

        if msg.callback then
            msg.callback(id, err)
        end
    end)
end

return M