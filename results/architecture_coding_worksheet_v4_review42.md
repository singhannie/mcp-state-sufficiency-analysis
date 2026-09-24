# Architecture Coding Worksheet - Review-Pass Version 4, FORTY-SECOND Pass

Scope: author-scored design reading from public descriptions only. This is not
an implementation audit, author consultation, or claim that the cited systems
fail inside their original scope. The worksheet asks what additional
MCP-integration atoms an MCP deployment must supply when applying each
architecture to the paper's running policies.

## Rubric

1. Record the cited source region used for the row.
2. Separate the original authors' stated enforcement claim from our
   MCP-integration inference.
3. Identify the enforcement boundary described by the original system.
4. List the policy atoms available at that boundary as described.
5. List atoms required by the paper's MCP policy but not specified by the
   original architecture.
6. State the adapter or placement move that would supply the missing atom.

## Rows

| System | Source region used | Original authors' claim | Boundary read for this paper | MCP atom source to supply |
|---|---|---|---|---|
| CaMeL | Sec. 5, Fig. 5 | Capability-tagged values and interpreter checks block unauthorized data flows. | Runtime boundary outside the model can enforce capability/dataflow policies over values it receives. | Stream adapter must supply ordered fragments, host-bound run id, and source/sink labels for MCP progress exfiltration. |
| Progent | Sec. 3 | Privilege policies constrain agent actions and policy updates. | Symbolic privilege checker decides declared action permissions and policy updates. | History or stream adapter must supply reconstructed content and prior-call atoms for policies over progress output or sequence history. |
| AgentBound | Sec. 3 | Server execution boundaries enforce least-privilege access control. | Server-side boundary can decide policies local to that server and request context. | Host/gateway must supply cross-server invocation history and public-sink labels for private-source/public-sink policies. |
| Wang et al. | Secs. 3.2--3.3, 4.9 | MCP policy-enforcement point labels cross-step flows and enforces tool-call policies. | Call-level PEP is close to the paper's sequence-engine placement. | Gateway must supply progress reconstruction, cache authorization context, and task continuity atoms for policies outside ordinary tool-call facts. |

## Register Rule

Rows are phrased as integration requirements: "as described, the architecture
does not specify a source for atom X; an MCP deployment must supply it via Y."
They should not be read as deficiency verdicts on systems whose authors made
different scoping choices.
