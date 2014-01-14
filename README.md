jwt2
====

Json Web Tokens - Hackett style

Getting Started
---------------

Create two local certs with the following commands:

````
makecert -n "CN=TempCA" -r -sv TempCA.pvk TempCA.cer

makecert -sk SignedByCA -iv TempCA.pvk -n "CN=SignedByCA" -ic TempCA.cer SignedByCA.cer -sr localmachine -ss TrustedPeople
````
