<?php
header("Cache-Control: no-cache");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Content-Security-Policy: default-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me; style-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me 'unsafe-inline' 'unsafe-eval'; font-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me https://fonts.gstatic.com; frame-ancestors *.fortifi.me:8090; connect-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me wss://screenshare.fortifiio.xyz https://screenshare.fortifiio.xyz ws://chat.fortifi.me:8443 wss://call.fortifi.xyz wss://call.fortifiio.xyz wss://*.twilio.com; media-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me blob: *.fortifi.cloud *.fortifi.xyz *.fortifiio.xyz *.fortifi.co *.fortifi.me:* https://storage.googleapis.com/fortifi-stage-attachments/ https://storage.googleapis.com/storage.fortifi.co/ https://api.twilio.com/");
header("X-Content-Security-Policy: default-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me; style-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me 'unsafe-inline' 'unsafe-eval'; font-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me https://fonts.gstatic.com; frame-ancestors *.fortifi.me:8090; connect-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me wss://screenshare.fortifiio.xyz https://screenshare.fortifiio.xyz ws://chat.fortifi.me:8443 wss://call.fortifi.xyz wss://call.fortifiio.xyz wss://*.twilio.com; media-src 'self' data: *.fortifi.cloud *.fortifi.io *.fortifiio.xyz *.fortifi.xyz *.fortifi.me:* https://storage.googleapis.com/cdn.fortifi.co/ https://maxcdn.bootstrapcdn.com/font-awesome/ https://www.google.com/ https://www.youtube.com/ https://ajax.googleapis.com/ https://www.gstatic.com https://maps.googleapis.com https://static.twilio.com/libs/ https://*.static.twilio.com/ https://www.google-analytics.com *.fortel.li *.fortel.fortifi.me blob: *.fortifi.cloud *.fortifi.xyz *.fortifiio.xyz *.fortifi.co *.fortifi.me:* https://storage.googleapis.com/fortifi-stage-attachments/ https://storage.googleapis.com/storage.fortifi.co/ https://api.twilio.com/");
header("X-Frame-Options: SAMEORIGIN");
header("Set-Cookie: e1d0dd2c6a_login=eyJpdiI6Ilhjb21JeVZDQnZWNUcyellWYVM5cWc9PSIsInZhbHVlIjoiUUVcL250NkNpQjRMOUlPdm9TXC9GTmhOcFwvdGtsSnhtZnNCdFNzVTF1U3dcL0UyXC9UdWc0aUJsUFZmVzZOT3Y3WkoydmZpUG5LamFEMDhGdzNSdlhcL2E2Sjd1NHZJMk5GdDZDeFRJMzdMN3FSS3VDWFwvTlg5QXdrbHVvSmtwRFdvaEp1NGJiaTA5blNza3ltdGp4SG1wR1wvRnk3NkRwQmZvNHgwM1RZenVZc1wvXC84cFEycjN5M0RWSDI0TmRDb1RaQXUwYXZEbG5mZW9tSFVcL2wxdjdsMnI0UHlFYkRXdHdPb2U4a1hMMm4wcEg1OWlrZlwvejVQR2xNRjNBMEt2aTZWWlg4dU9yZ3pqRjB1WE9Vd3A4TVdqWHdIUk54VCtaNGNSMWNpTTYxQVJcL3lJXC9oZ3R1MzNIVXl1WTVsZmpUamgyMUVRUzRzcVRNSWdXUGhtWnpUbHc1RFBicm0xUVwvbWQ0bW1PVkIzUTBTSGwxcGx4a0Z6NVdNTUxMbGlFMDd6R2oybFZDN1lRKzFVczVrRmxmdjBzQVIwS3NiczdMRzBlZklpenRjMlY1TWhHcTEwcFVZZ3IxN0tnXC9relhDVG4wbGhNSHlHOVR1XC9VRGZYM0oxY1VTR2RiQUxQVTJLbkkxVytvcVwvNlNpMkVlXC9QQ2E4YnZSbXNqN1E3RFdQeDVQSHk0N0pTeWZTbW1UVko2UUFcLzA4aWpXclZ0NEtGUzV1YldRcFZpRGdPbjMrNEd2ajd1MUl1Y2dpN0xtcklnczB2Zm1KN1RUeFp6Y284MVd2K0REUXAySUFIK0ZJMkNta29OeGNqOXdROWFTTjRCNjJLVlBsMFQrZFwvV3RvTEZmTUdFWk1VZndObW1Hd2tHXC9FUktIYno4QlB6XC9TNFBDUWZ6RFhFYTRaNm9WUUdVXC9DbjlOM0RlTGZ1eGw0dEdvUmViWURDT3NoaldXUkMwaldHcGM3ZlRLWWxjMmpWWTVTSW1EaE1DQ0ZGM0JGWGJPQ1RBNUF0bGNkSktBTWlaeHpoa0NwdllyNWltZmRjTmwySHE3ZHZRcEwxeXlvNVp3MXNqMXMrRDByeElXcE4xbXB6bUFzbG9IT1ZuNEVITmxDcTdEWDJnMk5yZzEyeWRZU2pIRWU5dFVDZWRVODZ1VCs0OVRVdU8xc2dhajJPTGVJVFRxTFl4YWFaalphRmdKV1c2YVhsVzREMjF0SnFhZWtTUnp2V3hGdnFZSlZSUXV4bTloMmNjelJYaTFWMDFEVDRZTWY2RUNPQzUxOTRcL3N5S1o1VTAxTDI4TmlGbnU5bEtYSmR4YWlPN1FMbktFdTlxUXFUSVVlclp3XC9jcjVWbDVPWVpqcllqVHljNlwvb0RDK1Z1b2FDZkc3YmJVUmJxRmZWZDJyV0ZkVmt3VkN2VVVtSTJkMmVOaUJtcURxWml0aWJTeHk2OWxIVkI4WDRYY1AyaHZpNmdxWDV5V0hyVUFqODcwTWhwVFE5TFhvZWorNzBHQllcL0pmeXJFTHNzeVorR1RiSGRVNlwvYlpicUV5UHJXYzVcL1NBYWsxZzk4bDREb2lIT2pqVVwvZ0VcL2JvaVBHbU9kTUJmMG5GbDdiN0RSVXoyTnVqVVhkbU44NG5mWkJraDY3RlhVMTErK3V6ZHNsZHU0TENoUEF0Uksrd0dza3NjTGFaQXZXcE9DWWhsRGRCeXRkRkU1SjRGQWxQZTZPMm5Ec25raFAzVEVjdE1uZXRvOEJ3c0g5alY1ZHJqNjNWazdNWmpCV2pqOVkrODBYTU5nS0ZPTWxueTJSSTFVT2lFTlhRc0VhdThCQTRGd2dmM1FCVUJpZEJYSUc2VDVYbCtkSFFMQ0ZNSHY4Mm8ySzBoWnBcL1A5ZDF0WTllT3JENnpHUkFmcEpVRjFkVDRsbExBUWw0QlZBMDFzaWlGWG1wMkZjSVc2VzBTMmQ5SU1nUnErMjJWVUp4aVpHbUpcL0J0NjNcL3Ria1FUT1dreVRiNGlyMm1uNkZ1OFZOMmIyZ3QwRmxXbzVycG4wMDVGazl3MUJMRlJZQzM2UDdhNGF3K3lLWU1lbGFGWk5oT0ZoXC94dGRGckhhZmRDVU9QYVJiM1lnbElsWUpQNVFwdVE3XC9nQUJFVDNlQlAyVjBVNWd0XC93NXZwWFRsNWlOOWtMRDUxTGNWd0RHTEtZeTZWZHJvcjBOOW5kcUEyS0RGcmlFR3NKV2N0NkZYeFBxTjRJSFwvNzZYZGVhckplWWpkM1dcLytad1YwNzRCbFpUQU1vWWFsSUR5a0k1SWVCRG1GVW84K1IrSytOemNFUnRpU2g1bFZ5WVp4OXhpeEd3MXVcL2tSc1ZLbVwveTBqWEVlUm5QUldwU1c4REN0eHdLWWZJSGVLWTdLdGlsVnBFaVhJNmQrZmlnNnY4Mk1VZytHT3BWUEJkWnJjSVY2T2xSM1FzTTQ4cXd2c3Urd1pHTTNWdzhVbFFwa1pRdlhDbmM4Z1prXC8yVjFZMGZYYTBGMEMwK1MxNnZxUnRRa2ZVUjJDWk9RVEtJV3NqZ3VEdTdYU0pIMkhZR0loK2l2aG1qT256MEVoXC84TVwveHo2amhMYmExSzhYc25ONFpCQm1BbGN3b2hKWmlaWUtYR3ZQQ3g4Znl6OFJYNHNQTzY1ZXlkZzlsOHNJRnZZMVllVmt4OWZlalloQ3MyRmVRblFUM01qU2g1SXFSbTRcL0dLZFljU09sOXMyWE11elpvOFdcL3lcL0RRbzA2MnlsSk11c3FlN3Nzd2NPSnFYUUZzOTZGXC83cGxyK056NWJxbWZ3eXBcL3ZFbUtHVWp6VkE4VVpicW5TclZEXC9CVHljcStOUDhUSXcyeHdVXC94VEhIcGowTlFUV3pWZmxwbFE9PSIsIm1hYyI6IjE0NTI1NGRjMjM5MzMzMmE0MDBmZTI2YjkyNmQ2YWNkM2EzNzVhMGQ4NGM5MWQyNzZiZmU5ZmMzN2Y5OTZkNTYifQ%3D%3D; expires=Wed, 26-May-2021 09:34:04 GMT; Max-Age=155520000; path=/; domain=fortel.fortifi.me; HttpOnly");
header("Location: /locked?return=/customers/40673510/billing/invoices&qs=currency%3DUSD%26customerId%3D40673510");
?>