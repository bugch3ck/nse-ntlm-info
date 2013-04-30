
--
-- Extract information from NTLM enabled IMAP services.
-- 
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
-- @author = "Jonas Vestberg"
--
-- Version 0.1
-- Revisions
-- 2013-04-30 - v0.1 - Published on github.com
--     

local stdnse = require "stdnse"
local string = require "string"
local imap = require "imap"
local base64 = require "base64"
local shortport = require "shortport"

local ntlminfo = require "ntlminfo"

author = "Jonas Vestberg"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {}


portrule = shortport.port_or_service({143,993},{'imap','imaps'})

local SOURCE = stdnse.get_script_args(SCRIPT_NAME .. ".source")
local DOMAIN = stdnse.get_script_args(SCRIPT_NAME .. ".domain")

action = function(host, port)

	local status, errstr
	local wks = SOURCE or 'TEST'
	local domain = SOURCE or 'TEST'

	local capa
	local msg1, msg2
	msg1 = base64.enc(make_ntlm_nego(wks,domain))

	stdnse.print_debug('NTLM type 1 message created: '..msg1)

	local conn = imap.IMAP:new(host, port)
	status = conn:connect()
	if not status then
		stdnse.print_debug('Failed to connect to IMAP server.')
		return
	end

	-- Send CAPABILITY command.

	status, capa = conn:capabilities()

	if not status then
		stdnse.print_verbose('Failed to determine IMAP server capabilities.')
		return
	end

	if not (capa and capa['AUTH=NTLM']) then
		stdnse.print_verbose('The IMAP server does not seem to support NTLM authentication.')
	end

	-- Send AUTHENTICATE NTLM command.

	status, errstr = conn:send("AUTHENTICATE", "NTLM")

	if not status then
		conn:close()
		stdnse.print_verbose('AUTHENTICATE command failed ('..errstr..').')
	end

	status, data = conn:receive()

	if not (data == '+') then
		conn:close()
		stdnse.print_verbose('IMAP server does not support NTLM authentication.')
		return
	end

	-- Send NTLM type 1 message.

	status = conn['socket']:send(msg1..'\r\n')
	status, data = conn:receive()

	-- Parse NTLM challenge message.

	if not (data:sub(1,2)=='+ ') then
		conn:close()
		stdnse.print_debug('Unexpected response to NTLM type 1 message.')
		return
	end
	msg2 = data:sub(3) -- remove the "+ " prefix

	-- Send empty NTLM authentication string.

	status = conn['socket']:send('\r\n')
	status, data = conn:receive()

	-- Logout and disconnect.

	status = conn:send('LOGOUT')
	status, data = conn:receive()
	conn:close()

	-- Parse NTLM type 2 message.

	local targetinfo = parse_ntlm_chall(base64.dec(msg2))

	return stdnse.format_output(true, format_ntlm_info(targetinfo))

end
