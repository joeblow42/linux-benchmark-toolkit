# Bodhi hands-on feedback

Notes from hands-on testing of the packaged toolkit. Use the draft pull request to record observations and discuss ideas for changes.

## Discovery in Dialog

- **Observed** — Selecting Discovery starts the run without showing a list of Discovery checks first.
- **Observed** — After Discovery finishes, Dialog exits to the terminal.
- **Expected** — Show the list of Discovery checks when that mode is selected. After a menu action finishes, display the outcome in a window with an **OK** button. Leave it open until the operator acknowledges it, then return to the previous menu. Exit the application only when the operator chooses to exit.
