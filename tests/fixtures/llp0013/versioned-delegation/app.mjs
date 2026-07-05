// Root grants shared-pkg fs:read. Two coexisting shared-pkg versions:
//  - top-level shared-pkg@2.0.0 imports helper-pkg but declares NO delegates
//  - nested shared-pkg@1.0.0 (under uses-old) declares an fs:read delegate to
//    helper-pkg but never imports it
// No single version both imports helper-pkg AND delegates to it, so no grant
// may reach helper-pkg. (ENG-22818)
import shared from "shared-pkg" with { grants: "fs:read:/tmp/allowed/**" };
import old from "uses-old";
console.log(shared, old);
