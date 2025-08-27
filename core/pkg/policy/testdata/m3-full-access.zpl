# This started life as milestone3 policy but has been updated as
# updates to ZPL and compiler have been made.

Define adapter as an endpoint with zpr.adapter.cn.

Define NextCloud as a service with endpoint.zpr.adapter.cn:'nc.zpr.org'.
Define RfcDB as a service with endpoint.zpr.adapter.cn:'web.zpr.org'.

Define NextCloudPing as a service with endpoint.zpr.adapter.cn:'nc.zpr.org'.
Define RfcDBPing as a service with endpoint.zpr.adapter.cn:'web.zpr.org'.

# Allow any valid adapter to access our two services.
Allow adapter to access NextCloud.
Allow adapter to access RfcDB.

# Allow any valid adapter to ping the web and nextcloud
Allow adapter to access NextCloudPing.
Allow adapter to access RfcDBPing.




