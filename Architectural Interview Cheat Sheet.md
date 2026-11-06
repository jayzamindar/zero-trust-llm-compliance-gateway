
Q1: What does extra="forbid" do in your Pydantic schemas, and why did you use it?

• Simple Analogy: Think of an elite airport security checkpoint. If a traveler shows up with a standard suitcase but has sewn an extra, unapproved hidden pocket onto it, the system flags it, stops the line, and rejects them immediately—even if the pocket is empty.
• The Technical "Why": By default, API frameworks ignore unexpected fields sent in a request payload. In a Zero-Trust environment, this opens the door to Parameter Pollution or Token Smuggling, where attackers hide malicious parameters inside a request to trick downstream AI models. By locking the ingress boundary down with extra="forbid", any request containing a single unapproved field name is instantly rejected with an HTTP 422 Validation Error at the perimeter.

Q2: Why did you build an Asynchronous Storage Abstraction instead of writing raw Redis queries?

• Simple Analogy: Think of building a music application. Writing raw Redis code is like hardwiring the app's code to only work with one specific brand of wired headphones. Building an abstraction interface is like installing a universal headphone jack. The app doesn’t care what is plugged in; it just sends the audio signals through the generic interface.
• The Technical "Why": If we wrote raw Redis commands (like await redis.hset) directly inside our API routes, our codebase would be tightly coupled to a database dependency. This creates two problems: vendor lock-in and slow testing. By creating the BaseTokenStorage abstraction, we decoupled the database. In production, we inject RedisTokenStorage for distributed horizontal scaling. In our automated test pipeline, we inject a fast InMemoryTokenStorage mock. This is why our 55+ tests run in a fraction of a second without needing a live spinning database container.

Q3: Why did you choose a "Fail-Closed" architecture for this compliance gateway?

• Simple Analogy: If the badge scanner at a high-security corporate facility breaks or loses power, a "Fail-Open" policy leaves the doors wide open so anyone can walk in. A "Fail-Closed" policy instantly locks all security turnstiles down, ensuring nobody gets through until the system is verified healthy.
• The Technical "Why": Enterprise data protection takes absolute precedence over system availability. If our internal data scrubbing engine or Redis cache goes down or experiences an outage, letting prompt traffic bypass inspection would cause catastrophic PII leaks to third-party endpoints. The gateway continuously tracks health checks, and upon any component failure, it immediately intercepts traffic and returns an HTTP 503 Service Unavailable response.

Q4: What is Token Smuggling, and how does your gateway stop it?

• Simple Analogy: Imagine an automated bank system that replaces the word "Secret Vault" with a plastic token. A bad actor types a counterfeit plastic token directly into their letter, hoping the system will mistake it for a real one and reveal the vault contents on the way out.
• The Technical "Why": Adversaries can type raw token structures (like [EMAIL_TOKEN_1]) directly into a prompt, attempting to exploit the gateway’s reverse-unmasking logic to exfiltrate cached sensitive data belonging to other user sessions. Our gateway enforces an outbound and inbound fast-path perimeter check. If any string contains forged compliance brackets before inspection, it treats it as a structural violation and returns an immediate HTTP 400 Bad Request.

Q5: Why did you use Unicode NFKC Normalization and Zero-Width character stripping?

• Simple Analogy: A security scanner is looking for the word "Secret". An attacker writes it using lookalike characters from an alternate keyboard alphabet (homoglyphs) or types hidden, invisible characters between the letters ("S [invisible space] e c r e t"). To a basic text scanner, it doesn't match the word "Secret".
• The Technical "Why": Attackers insert invisible zero-width spaces (\u200B to \u200D) or compatibility variants to break regex matching boundaries and smuggle PII like Social Security Numbers out to cloud LLMs uninspected. Our gateway pre-processes raw strings, flattening compatibility glyphs to standard ASCII and stripping out hidden evasion characters before the scanning engine evaluates regex matches.