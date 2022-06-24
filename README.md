# privacy-systems-kms

Three main entities:
    Server
    Operator
    Client

Download from release the kms.zip, there will be 3 .jar files, these are the exeutable.

To run:
$java -jar filename.jar

If running in intellij, make sure that multiple instances is enabled in build configurations for multiple Clients/Operators.

When executing Client or Operator Server ip will be asked, press enter (no input) for local server.

From there just operate as normally, each entity as its work flow menu, server menu is a little wonky and there is no need to operate it at the moment.

Example usage:

1. Server started.
2. Initiate Operator (n times for as many operators as you want)
    3. Press enter when Ip of server is asked for local host
    4. Each operator will have its own Domain created from initial Trust
    5. Go to Hsm menu to add/create more hsm, in the system, if so desired
    6. Go to Trust menu and create new trust, follow configurations, such as what hsm or operators to add to trust
    7. Sign new created trust as operator, unsigned trust can be viewed as well as the operator trust signatures, go to each operator to sign the trust on which it participates, "Show participating trust" can be used to get Id of Trust on which the operator participates.
    8. Sign Trust with hsm, success if operator signatures satifies the Quorum value, else no success, can verify this by vieweing Trusts and checking that the previously unsigned Trust was now moved to the signed Trusts list, the Trust signature can also be verified.
    9. Go to Domain menu and create a new symmetric domain

10. Initiate Client
    11. Type id of Domain to use
    12. Can now encrypt or decrypt files using that Domain


