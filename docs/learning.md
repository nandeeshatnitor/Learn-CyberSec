# Interactive learning sessions (phase 3)

The static guide from [research.md](research.md) is turned into a guided exercise. The philosophy:
*understand → investigate → try → get feedback → hint → try again → solution*. The full answer is
never shown up front; the student earns it, or chooses to reveal it and pays a small, configurable
cost. The static reference guide is still available on the CVE page, tucked behind a "spoiler" fold.

Code: `backend/app/learning/` (challenge, rubric, scoring, tutor), `app/services/learning_service.py`,
`app/api/routes/learning.py`, `frontend/src/components/learn/`, page `/learn/[cveId]`.

## The challenge every guide carries

`LearningGuide.challenge` (built by `learning/challenge.py` right after the guide is validated):

| Part | Notes |
| --- | --- |
| Learning objectives | One per task. |
| Prerequisites | What the student should bring (reading a CVE record, how software receives input, a local/authorized lab). Deliberately *not* the guide's own "prerequisites" claims: those are conditions of the vulnerability and give answers away. |
| Tasks (up to 5) | Identify the vulnerable **component**, the vulnerable **input**, **reproduce** the documented behaviour safely, **explain why** it occurs, identify the **remediation**. A task is left out, with a note, when the sources give too little specific detail to check an answer (for example no reproduction was established). |
| Verification criteria | What a complete answer covers, without giving it. |
| Hints (3 per task) | See below. |
| Solution | The supporting claims, cited; for the reproduction task also the documented steps and commands, shown as text. |

Everything private (accepted answers, hints, solutions) is derived from claims the research validator
already grounded in retrieved sources, so nothing is invented, and is **redacted** before any browser can
fetch the guide (`Challenge.redacted()`); it is served only through the actions that earn it. The guide
`generation_version` was bumped to `2`, so guides generated before this phase regenerate.

### The hint ladder

| Hint | What it is | Default cost |
| --- | --- | --- |
| 1 | A direction only: generic wording plus which sources to read. Contains no accepted answer term. | −5 |
| 2 | One source sentence with the answer terms masked (`█████`), or a slightly sharper generic hint. Never contains an accepted answer phrase. | −10 |
| 3 | The source sentence in full, cited, with the excerpt. | −15 |
| Solution | Every supporting claim, cited. | −30 |

The rule that hints 1 and 2 leak nothing is checked **in code** at build time (whole-word, separator-
and case-insensitive; a source title that would leak an answer term is replaced by its ID) and has tests.
Hints must be requested in order. Each reveal is recorded (number, time, content, sources), and evidence
excerpts are returned only from hint 3 on.

## Sessions

`LearningSession(id, user_id, cve_id, started_at, completed_at, status, hints_used, solution_revealed,
score)` with status `NOT_STARTED / IN_PROGRESS / COMPLETED / ABANDONED`, plus per-task progress, hint
events, answer attempts and tutor messages (migration `0004`, see [data-model.md](data-model.md)).

* The guide, its private challenge and the evidence are **snapshotted** into the session at creation, so
  regenerating the guide never changes a session in progress. Scoring rules are snapshotted too.
* Tasks are done in order. A session ends by `complete` (every task answered or revealed) or `abandon`;
  a new one can then be started. Creating a session again while one is active resumes it.
* **Identity.** There are no accounts yet. The web app keeps a random token in an HttpOnly, SameSite=Lax
  cookie (`cvele_learner`, unreadable by JavaScript) and forwards it to the API in `X-Learner-Token`. Only
  a SHA-256 of it is stored as `user_id`, so the database never holds a usable token and a session is
  visible only to the token that created it (anyone else gets 404). Real accounts can replace this later
  without a schema change. Clearing cookies orphans the sessions.

## API

`POST /api/learning` `{cve_id}` · `GET /api/learning/by-cve/{cve_id}` · `GET /api/learning/{id}` ·
`POST …/start | complete | abandon` · `GET …/hints[?task_id=]` (revealed hints with number, time,
content and evidence, plus what comes next) · `POST …/hints` `{task_id, number}` (reveal the next hint) ·
`POST …/tasks/{t}/answer` `{answer}` · `POST …/tasks/{t}/solution` · `GET …/tasks/{t}/solution` (once
finished) · `POST …/tutor` `{question, task_id?}` · `GET …/tutor`.

Reveals are `POST`s, not `GET`s, because they change state (score, history): a link prefetch must never
cost a student points. 401 no/invalid token, 404 unknown or not yours, 409 not allowed in the current
state, 422 invalid input, 429 rate limited.

## Answer checking

Text answers are checked against each task's **key points**: phrases (or, for explanations, sets of
concept words) that show the student has the point. Every required point present → `correct`; some →
`partially_correct`; none → `incorrect`. Feedback says what was covered and what is missing **by label**
("the specific module, function or feature", "the fixed version or setting"), points back at the sources,
and never echoes the expected answer. A correct answer reveals that task's solution; wrong attempts cost
nothing. Solutions require at least one attempt first (`LEARNING_SOLUTION_REQUIRES_ATTEMPT`).

This is deliberately transparent and offline, and it has limits: it is keyword/concept matching, not
understanding. A correct answer phrased with unexpected vocabulary can be marked partial, and an answer
that name-drops the right words can pass. It is meant to give a student quick, honest feedback, not to
grade them. Key points come from a heuristic extraction over the guide's claims (component nouns and
identifiers, header/parameter names, observed results, cause sentences, fix verbs and versions), so task
quality tracks the quality of the underlying guide.

## Scoring

Start 100; hint 1/2/3 cost 5/10/15; a solution costs 30; never below 0. Configure with
`LEARNING_START_SCORE`, `LEARNING_HINT{1,2,3}_PENALTY`, `LEARNING_SOLUTION_PENALTY`. The rules are copied
into each session when it starts. The UI plays the score down: a small counter, honest about hints used
and solutions revealed, and a summary that says what matters is what the student now understands.

## The AI tutor

Ask "Why does this happen?", "What should I investigate next?", "What does this parameter mean?", "Can you
explain the vulnerability?" or anything else. The tutor sees the CVE metadata, the research evidence
(snapshotted per session), the current task, the hints already shown, progress and the recent conversation.

* **Grounded.** Every technical statement is a claim with citations, validated by the same code that
  validates guides (invented versions, identifiers, URLs, numbers and uncited claims are removed). With a
  model configured (`ANTHROPIC_API_KEY`) it writes the answer; without one it quotes the most relevant
  source sentences. If the evidence does not cover the question it says so and does not guess.
* **Source transparency.** Each answer part lists its source (title, link) and the exact excerpt it rests on.
* **No spoilers.** While the current task is unresolved and its explicit hint (3) has not been shown, any
  passage that would answer it is **withheld from the model** (also when the answer hides inside an
  identifier such as `TemplateRenderer.resolveHint()`), and any sentence that would earn a "correct" answer
  is removed from the reply. A question that just restates the task gets a nudge and a pointer to the hint
  ladder instead. This is enforced in code, not by asking the model nicely.
* **Safe by scope.** Questions about attacking, scanning or testing systems the student does not own,
  or that name non-local hosts, get a fixed refusal that redirects to a local or authorized lab; replies
  never contain non-local hosts or commands that pipe downloads into interpreters; lab questions carry a
  reminder. Student text and evidence are data in one JSON document; the model has no tools.
* **Limits.** Per session and per client per hour (`LEARNING_TUTOR_PER_SESSION_PER_HOUR`,
  `LEARNING_TUTOR_PER_CLIENT_PER_HOUR`), question length capped.

## Frontend

`/learn/[cveId]`: **left** objectives (with status), progress bar, score, prerequisites; **centre** the
current task with its prompt, verification criteria, research context (CVE description, affected software,
sources to read), an answer box, *Submit answer*, *Get Hint n (−k points)*, *Reveal solution (−30)* with a
confirmation step, and feedback; **right** the AI tutor (with suggested questions), the hint log and the
sources. After answering or revealing, the student stays on the task to read the solution, then continues.
All state is server-side; the page can be reloaded or resumed. The browser talks only to same-origin route
handlers (`app/api/learning/…`): fixed path/method allow-list, cross-site POST refusal, sanitised
`X-Forwarded-For`, fixed error fields, no cookies forwarded. All text is rendered as text; links via
`SafeLink`.

## Known limitations

* Not exercised against the live Anthropic API (no key or network in development): the model-backed tutor
  is tested with fake models, including ones that obey hostile pages and try to leak answers.
* Anonymous identity: clearing cookies loses sessions; there is no cross-device progress until accounts exist.
* The CVE description shown as research context is real public metadata and can itself name an answer
  (for example the vulnerable header); the exercise is to investigate and explain, not to hide the record.
* Task and answer quality follow the guide: thin sources give fewer, coarser tasks (with a note saying so).
