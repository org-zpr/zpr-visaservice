define WebService as a service with user.bas_id:1234.
define DbService as a service with user.bas_id:4567.

allow WebService to access DbService.
allow content:green services to access content:brown services.



