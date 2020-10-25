#!/usr/bin/env python3

SP_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIICnTCCAYUCBgF1YNB/jTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdwYW1z
YW1sMB4XDTIwMTAyNTE3MjkzOFoXDTMwMTAyNTE3MzExOFowEjEQMA4GA1UEAwwH
cGFtc2FtbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMvTJSjKQ6Jp
whcr2Ck16lhV81lWwZoQ7Ey67UumXFok9qBHoteD1sv3E6JHJq6JZqvTMBDqkKpA
pWiNBtc3sa5xD6o+L4atS5zw/oPdQJ4uZjYi/g4uIwBHdLIeyptSprqkFP2LRWa4
nJgT0JFVVdugFSGR6ovyCS9n7WDP9B7BhFA5eIdvcbLuLg2UmbC2EMy8bXH0U10q
tiyexLjKsS726V1Ut5uJszMBz58Wroftt0rL+wJ0T7vX8bDw5Jded3ipYwE30Izv
NIQm8ZwocYg1EpL0oa9Fyl3qCFvHdMjQa3+r+BWPE0xmvQwCaVPgBp6K8+0QLUKf
Fu649TtcomcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVDkKgRk+GVrT1NkgHAI1
JCuVqeKRQZrpJmJ1wZ3OlYeQXduqzF01X+ut4CaD7PLtfNZPziukZvygNRx96/Nc
DK7HMZEv6OMCNVeIViZIkDB/F3ZUy2QjldbrUkNxuFL996gPQ3A71ADkL0yO5NYz
UOFH6I8Np/LgcZgcYGd6nMABSKxmzsGUQO6hVL1sMDTEPLIJoDMAE31n8+vTGdJR
QZBw35Ini5Do6luzpUvxkyQfisei7hoiw0v6j6fsW+yibMc4XbkBk22lodEGY3RE
B/cKlvvA6cXgvYlADHtV0/3Yea9gRZER8jgMf0kpGoxkH9QaORw7s/mV7/W+RS1e
5w==
-----END CERTIFICATE-----"""
SP_CERTIFICATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAy9MlKMpDomnCFyvYKTXqWFXzWVbBmhDsTLrtS6ZcWiT2oEei
14PWy/cTokcmrolmq9MwEOqQqkClaI0G1zexrnEPqj4vhq1LnPD+g91Ani5mNiL+
Di4jAEd0sh7Km1KmuqQU/YtFZricmBPQkVVV26AVIZHqi/IJL2ftYM/0HsGEUDl4
h29xsu4uDZSZsLYQzLxtcfRTXSq2LJ7EuMqxLvbpXVS3m4mzMwHPnxauh+23Ssv7
AnRPu9fxsPDkl153eKljATfQjO80hCbxnChxiDUSkvShr0XKXeoIW8d0yNBrf6v4
FY8TTGa9DAJpU+AGnorz7RAtQp8W7rj1O1yiZwIDAQABAoIBAFDX3KNDJnRi0jLy
lvgxhFOpM645tOxwzejZM4mP4I14n8GO6E3m4ulfhJAW/Ia5xNleGHB9OQfuQC0p
0o7GblksSvRRWfRnA9ip1aljtl+HM89BLddeAU/5B5YmlGHq9GqO7ixqcwp9Ks8+
/LjIShekdP0trQP46h+9bu+5S7Buh4vU3xSJoz3ENIBBfXghU0ESrdRrhaLieyLP
Y81Ddevd6C8MUeny16RGBN680+i61NixLK3ZP8IMTU0jS1CKlpARhMiRKgiogMDz
bWA1FnlmYvKbTxJc4nX23RbuRFWJIZZiL2Yp55QJo2cE6n2a+iXWsg6nIlfwTQcg
UXmMlRECgYEA8sPMve3tRP0jKNiD+rYwAYN02Yy8kyAzwkUkF/D38hnERaXI1bre
wtOUQnrym55y1TEA0MlxfpgecbuIqT5WX1d9/1AXy5QWhaSMmN6wpnuPdjpXfo2n
m4z9Tx9yu13s+WVk4QFjlm+eCsM5QdsbHoNpr2RcWLTwerJNbHs/DPsCgYEA1u/e
ua4Bf04OH/iEUrJJmLAE4BJtriwQSF8NucEdJkL0jfZVw/6tpDa3xwrfcZRXyZ9M
dhW8EdnDKF9KpIfVEYtau3XRgHkbZvIn0292vhWFj353+PGjBSsporRZp96c3F84
CzzPs/SBtugXPMJIduFj4iygrNWCmRcUzZKTbIUCgYBne08rJuCdJ8p0/tZDaKXN
/1sv4O4BSRjHFvHrwqvuZ01i4uhZMu8B3W61Z/NCoqgQeHMAjN30OKPBl08J1ai7
u2/aBSoffWCcVygXgdWLIeBlZTkmmPt5MwBHWgBuHfuF09LMlur8lVeo/s7JY7yL
pTjHquAyb+6SXq7iLycRQQKBgDyj7FjCqRV7tix69wpF1tHHR3jYei1brTRd7Qdt
XoX++fRbfZMQdXkRHwR/Is9upN3znaTrOOZoY9EuIWcOE6UhhfXBpdvzTzHaPDZB
CmVSuR3k9oA73FyG8vY+n9Tmz6a1DqDNBWSmJTqvfG7d+Yfgy0dyg9p/WptKkcn2
ArXpAoGBAOmLmYeCYLBmp2G1iTuaAfahO6P7GEgsyTyhgG5Gc7R+HLmVQ7tDH5m7
UERm+kmM/mvW36EI4Hd+dg4rWQcUW6Q26MzQ2dGsnOF+k3OhMjlqSo7NG0y35kYA
tFsBABw9N2SKStyoGd58mI7+chqO3RrdqM8VFCJe+ib/O4RmenJo
-----END RSA PRIVATE KEY-----"""
IDP_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIICmzCCAYMCBgF1YORNSDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0
ZXIwHhcNMjAxMDI1MTc1MTE2WhcNMzAxMDI1MTc1MjU2WjARMQ8wDQYDVQQDDAZt
YXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqNhRyL3BDO5mx
B/ge0uv4bcy4CaDRAxybQIwgjmnsNMR0NI31Gm02EwCto1h8r8VnjjadwD0hGv/R
1SCSh86EvqzUggJNqMGGqzAZLUZLlQIuqeA2OYXDdhh5mZYfAy9hzDgbqfZ3Mhft
vwH0ydEdRSKbMuSy0FMGRjyzAF8EujwOSGCX7SGjEjQM5O2tTZt/LqOwSuyUYvXt
6YX9h3GPnrOVjMMzj6+qACGBG3W6dzcPjN33lXvCQVCG2VyRrR58oREULvx9R//M
sr6bfleWaZr1RX+yKUZajrF6XXg2NPCAZ/D9hjopQL/gfymYnHV+uSL+IvOumYfA
9OUekulVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKP0e4WOn1AB0nLJmrX9VwYh
i/FsDtPE4YOpimd81G2h369dJ+2uecFnssr0EpypMFUKW4XaXiEdXnBW67JSvIVb
MswEm2R7AErxhHNXod3x3WRd5PNGh8XUP12ov8oAHaOj0846CMd8D1NhoY8P2EWP
rvOnETouTFVYfpbHuXbgi2TzQuwrNzDKy/HPBtNpZsPNh2poO4YUp5MmVxtv122r
9gjxaE08itxU+hy44OrTJMzuo02r3btyLSJjz9iWCOiA3Pd7pnHUIGMcw11x35AJ
QC87Ui6cx7rqC/iOPQ0pLOClW4hJwz8z0xRytVFxNEwmuzNlzkSag9MxaJgHjLA=
-----END CERTIFICATE-----"""

IDP_DISPLAY_NAME = "Keycloak IDP"
IDP_ENTITY_ID = "http://localhost:8080/auth/realms/master"
IDP_SSO_URL = "http://localhost:8080/auth/realms/master/protocol/saml"
IDP_SLO_URL = "http://localhost:8080/auth/realms/master/protocol/saml"

HTTP_PORT=9000
HTTP_HOSTNAME="localhost"
HTTP_BIND_ADDRESS="0.0.0.0"
SECRET="secret"