local typedefs = require "kong.db.schema.typedefs"
local openssl_x509 = require "openssl.x509"
local ngx_time = ngx.time

return {
  name        = "cas",
  primary_key = { "id" },

  fields = {
    { id             = typedefs.uuid, },
    { created_at     = typedefs.auto_timestamp_s },
    { cert           = typedefs.certificate { required = true }, },
    { tags           = typedefs.tags },
  },

  entity_checks = {
    { custom_entity_check = {
      field_sources = { "cert", },
      fn = function(entity)
        local cert = openssl_x509.new(entity.cert)
        local not_before, not_after = cert:getLifetime()
        local now = ngx_time()

        if not_before > now then
          return nil, "certificate unusable, \"Not Before\" time is " ..
                      "in the future"
        end

        if not_after < now then
          return nil, "certificate expired, \"Not After\" time is in the past"
        end

        if not cert:getBasicConstraints("CA") then
          return nil, "certificate does not have \"CA\" basic constrain set"
        end

        return true
      end,
    } }
  }
}
