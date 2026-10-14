package llm

import (
	"context"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
)

// Completer answers one prompt. temperature is 0 for the first attempt and
// higher for the single retry, because the same prompt at temperature 0 would
// return the same bytes.
type Completer interface {
	Complete(ctx context.Context, system, user string, temperature float64) (string, error)
}

// Interpreter reads a request through a model: the prompt is
// intent.FormatPrompt's, and the reply must pass intent.Parse.
type Interpreter struct{ M Completer }

// Interpret asks the model for the actions of request. A reply that fails
// intent.Parse is retried once at a higher temperature; a second failure is
// an *intent.Unclear carrying the parser's reason, and nothing is guessed. Any
// other error is the backend's: the model could not be reached or answered
// with an error.
func (i Interpreter) Interpret(ctx context.Context, c intent.Context, request string) ([]intent.Action, error) {
	system, user := intent.FormatPrompt(c, request)
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		temp := 0.0
		if attempt > 0 {
			temp = 0.3
		}
		reply, err := i.M.Complete(ctx, system, user, temp)
		if err != nil {
			return nil, err
		}
		acts, err := intent.Parse([]byte(strings.TrimSpace(reply)))
		if err == nil {
			return acts, nil
		}
		last = err
	}
	return nil, &intent.Unclear{Why: "the model's reply was not a valid action list: " + last.Error()}
}
