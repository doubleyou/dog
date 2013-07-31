-record(dns_header, {
    id                  = 0                     :: 0..65535,
    qr                  = 0                     :: 0..1,
    opcode              = 0                     :: 0..15,
    aa                  = 0                     :: 0..1,
    tc                  = 0                     :: 0..1,
    rd                  = 0                     :: 0..1,
    ra                  = 0                     :: 0..1,
    rcode               = 0                     :: 0..15
}).

-record(dns_question, {
    name                = []                    :: [binary()],
    type                = 0                     :: 0..255,
    class               = 0                     :: 0..255
}).

-record(dns_resource_record, {
    name                = []                    :: [binary()],
    type                = 0                     :: 0..65535,
    class               = 0                     :: 0..65535,
    ttl                 = 0                     :: integer(),
    rdata               = <<>>                  :: binary()
}).

-record(dns_record, {
    header              = #dns_header{}         :: #dns_header{},
    question            = []                    :: [#dns_question{}],
    answer              = []                    :: [#dns_resource_record{}],
    authority           = []                    :: [#dns_resource_record{}],
    additional          = []                    :: [#dns_resource_record{}]
}).
