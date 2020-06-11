# NetSec-App-written-in-Java-RSA-DH-STS-
An app that uses DH-RSA-STS protocols and make a server-client app for making voice calls!
Description of protocols and measures to deal with vulnerabilities
This work requires us to develop various protocols that will ensure secure communication between 2 users on a network.
To achieve this we developed 3 different methods of secure communication
1st. Encapsulation: the method by which users exchange their public key and encrypt the data they want to exchange with their public key and decrypt it with their private key.
Of course, the questions that arise are that we know for sure that every user is the one who declares that they are, that is, that we will prevent attacks (man in the middle) as well as attacks aimed at intercepting some memories and retrieving them ( replay attacks). 
To prevent this type of attack we used some kind of tools. 
One of them is the use of certificates, ie each user has a certificate signed by a CA, ie an entity that is trusted by both. 
As a result, each user has to own a public-private couple. key as well as his certificate which contains his public key.
So instead of sending users only their public key, they send their entire certificate and on the side of each user a check is made which verifies that their certificate is signed by the specific entity they trust. 
But that is not enough to confirm that we have eliminated the risk because someone can steal the certificate and send it.
To eliminate this risk after checking the certificates then each user will create a digital signature which he will sign with his private key and will be sent to the other user.
Once the signature is received by users, it will be checked with their public key that the signature is valid and thus we will verify that the person we are communicating with is indeed the one who supports it. 
As far as Replay attacks are concerned, we have come to the conclusion that every message must have a unique identifier that will characterize it. 
So we created a generator that produces each time a random uid which in each memory exchange will be inside and just arrives at the user. will be saved within if map. 
In case a third party wants to steal a memory and send it again then it will fail because the user part will contain the check for any special uid in the map so we cover as a whole in replay Attacks Of course, the best security for such attacks would be to use timestambs, but time did not allow us to do so.
2nd. Diffie-Hellman (DH) Protocol: This protocol allows two entities, without prior communication, to exchange a common key through an unsafe communication channel. The user calculates a secret key a which is not going to reveal at any stage of the protocol and the random numbers g, p by selecting for p a first number then sends the message to the other user: g, p, ga mod p. The other the user receives the message and in turn selects a secret key b, and sends the message back to the user: gb mod p. After exchanging messages, both entities know a number that is not known by anyone else, gab mod p. Of course, this way of safe communication also faces serious risks. The first serious risk is again the authentication, ie we know that the person we are communicating with is the one who states that he is and not a third party (man in the middle). To prevent this risk, we will use certificates. . That is, each user will have in his possession if a certificate which will include his public key but also the user will have his private key. This will allow users to exchange their certificates and then check if they have signed the same entity (CA) they trust. If they do not have a signature from the same entity then the communication will end. Each user will then create a digital signature that they will sign with their private key and be sent to the other user. Once the signature is received by the users, it will be checked with their public key that the signature is valid and thus in this way we will verify that the person we are communicating with is really the one who supports. As far as the next danger is concerned, relay attacks are the retrieval of the same memories that have been branched out during the communication. We will deal with this again with the use of the uid generator which will produce if unique and random string which will characterize each memory and so on.
