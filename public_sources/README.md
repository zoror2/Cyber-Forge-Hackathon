# Public input for AI drafting

These files contain reviewed public API descriptions and invented example data.
Groq receives these files only. Customer connector IDs/names, endpoint edits,
database records, secrets and `.env` are never part of its prompt.

To add a new vendor:

1. Copy a JSON file and choose a unique `id`.
2. Read the vendor's official docs. Set its public documentation URL, public API
   endpoint, supported GET auth shape and target `user`, `device` or `event` entity.
3. Write a short public description of fields, dates and pagination. Include at
   most 10 **synthetic** records with the same structure as the documented response.
   Never copy a customer's response, token, host, email or account identifier here.
4. Keep `classification` set to `public_documentation_and_synthetic_examples`.
   Leave `auth.secret` out; the app uses a placeholder to fill locally later.
5. Review the file in a PR, run tests, then restart the API so it reloads the list.

The AI proposes `items_path`, pagination and field mapping. The app supplies the
reviewed URL/auth shape, limits, disabled schedule and customer-selected ID/name.
Generated paths must exist in the public examples, and every example must map
successfully. This checks structure, not every semantic assumption: a person
must inspect the result and test the real connection.

This first version supports the current GET/JSON engine. Unsupported login
flows, POST searches, XML and vendor protocols need engine work before drafting.
There is intentionally no API for uploading arbitrary private text or samples.
