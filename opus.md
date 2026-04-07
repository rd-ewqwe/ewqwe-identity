Create 2 web applications. one in the `wallet` folder and one in the `webapp` folder.
Both applications use Typescript, Deno, Vite and Tailwind CSS. No js framewrok like React or Vue.

The wallet application will ultimately be running on the mobile phone and manages W3C digital credentials stored on the secure element of the phone.
The digital credentials are specified in this document: https://www.w3.org/TR/digital-credentials/.
The wallet applications has 3 main functions:
1. Get credentials from Attestaion Providers (APs) after user authentication.
2. Store credentials securely on the phone.
3. Present credentials to Relying Parties (RPs) after user consent using the W3C Verifiable Credentials standard and OpenID Connect for Verifiable Presentations.

The webapp application is a demo Relying Party (RP) that requests credentials from the wallet application. Is based on the code found here: https://demo.digitalcredentials.dev. It then sends the credentials to a backend server for verification and displays the verification result to the user. The backend server wil be developped in Rust in this same project later. The webapp application has 2 main functions:
1. Request credentials from the wallet application using OpenID Connect for Verifiable Presentations.
2. Send the received credentials to the backend server for verification and display the result to the user
It gives the ability to show debug information about the received credentials and the verification process.