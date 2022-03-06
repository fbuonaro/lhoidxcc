local lhauth = {}

local cjson_decode = require( "cjson" ).decode
local cjson_encode = require( "cjson" ).encode
local resty_openidc_authenticate = require( "resty.openidc" ).authenticate
local resty_openidc_bearer_jwt_verify = require( "resty.openidc" ).bearer_jwt_verify
local resty_openidc_introspect = require( "resty.openidc" ).introspect
local clone = require "table.clone"

-- { op -> opts }
local opts_by_op = {}

-- openid provider
local HEADER_OP = "X-LHAUTH-OP"

-- reset lhauth headers
local function reset_headers()
    ngx.req.clear_header( HEADER_OP )
    ngx.header[ HEADER_OP ] = nil
end

-- handle the error and/or results of a cookie authentication or login attempt
-- on success, place the op, other things into the header
local function handle_session_authenticate_res_err( op, res, err )
    local json_res = cjson_encode( res )
    local json_err = cjson_encode( err )

    ngx.log( ngx.DEBUG, "handle_session_authenticate_res_err: res: ", json_res, " err: ", json_err )

    if err or not res then
        ngx.log( ngx.ERR, "session authenticate failed err[", json_err, "] res[", json_res, "]" )
        return nil
    end

    ngx.req.set_header( HEADER_OP, op )
    ngx.header[ HEADER_OP ] = op

    return res
end

-- handle the results of a jwt verify attempt
-- on success, place the op, other things into the header
local function handle_jwt_verify_res_err( op, res, err )
    local json_res = cjson_encode( res )
    local json_err = cjson_encode( err )

    ngx.log( ngx.DEBUG, "handle_jwt_verify_res_err: res: ", json_res, " err: ", json_err )

    if err or not res then
        ngx.log( ngx.ERR, "jwt verify failed err[", json_err, "] res[", json_res, "]" )
        return nil
    end

    ngx.req.set_header( HEADER_OP, op )
    ngx.header[ HEADER_OP ] = op

    return res
end

-- handle the results of an introspection verify attempt
-- on success, place the op, other things into the header
local function handle_introspection_res_err( op, res, err )
    local json_res = cjson_encode( res )
    local json_err = cjson_encode( err )

    ngx.log( ngx.DEBUG, "handle_introspection_res_err: res: ", json_res, " err: ", json_err )

    if err or not res then
        ngx.log( ngx.ERR, "introspection failed err[", json_err, "] res[", json_res, "]" )
        return nil
    end

    ngx.req.set_header( HEADER_OP, op )
    ngx.header[ HEADER_OP ] = op

    return res
end

-- ensure that opts contain all required fields
local function check_opts( opts )
    assert( opts[ "redirect_uri" ] )
    assert( opts[ "discovery" ] )
    assert( opts[ "client_id" ] )
    assert( opts[ "client_secret" ] )
    assert( opts[ "post_logout_redirect_uri" ] ) 
    assert( opts[ "scope" ] ) 
    return true
end

-- load into opts_by_op the resty.openidc.authenticate opts in 'opts_json_filepath' 
-- for provider 'op'
function lhauth.load_opts( op, opts_json_filepath )
    assert( op )

    local opts_json_file = assert( io.open( opts_json_filepath, "r" ) )
    local opts_json = opts_json_file:read( "*all" )
    opts_json_file:close()

    local opts = cjson_decode( opts_json )
    assert( check_opts( opts ) )

    opts_by_op[ op ] = opts
end

-- check if authed: if yes, set headers; if not, force authe through redirect
-- op: string, identity provider
-- scopes: string, scopes to request access for separated by spaces
function lhauth.login( op, scopes )
    reset_headers()

    local opts = opts_by_op[ op ]
    if scopes then
        opts = clone( opts )
        opts.scope = scopes .. " " .. opts.scope
    end

    local res, err = resty_openidc_authenticate( opts )

    return handle_session_authenticate_res_err( op, res, err )
end

-- check if authed using cookie/session: if yes, set headers and return res; if not, unset headers
function lhauth.check_cookie_authenticated( op )
    reset_headers()

    local res, err = resty_openidc_authenticate( opts_by_op[ op ], nil, "pass" )

    return handle_session_authenticate_res_err( op, res, err )
end

-- check if authed: if yes, set headers; if not, exit( forbidden )
function lhauth.require_cookie_authenticated( op )
    reset_headers()

    local res, err = resty_openidc_authenticate( opts_by_op[ op ], nil, "deny" )

    return handle_session_authenticate_res_err( op, res, err )
end

-- check if authed via authz bearer access token jwt: if yes, set headers and return res; if not, unset headers
function lhauth.validate_via_jwt( op )
    reset_headers()

    local res, err = resty_openidc_bearer_jwt_verify( opts_by_op[ op ] )

    return handle_jwt_verify_res_err( op, res, err )
end

-- check if authed via introspection: if yes, set headers and return res; if not, unset headers
function lhauth.validate_via_introspection( op )
    reset_headers()

    local res, err = resty_openidc_introspect( opts_by_op[ op ] )

    return handle_introspection_res_err( op, res, err )
end

-- logout
function lhauth.logout( op )
    reset_headers()

    local res, err = resty_openidc_authenticate( opts_by_op[ op ], "/logout" )

    if err or not res then
        ngx.log( ngx.ERR, "logout failed err[", cjson_encode( err ), "] res[", cjson_encode( res ), "]" )
        return false
    end

    return true
end

return lhauth;
