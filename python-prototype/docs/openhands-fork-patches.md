# OpenHands Fork Patches

## Overview

We maintain a vendored fork of OpenHands at `vendor/openhands` with patches on top of `upstream/main`. This allows us to implement fixes and improvements while working through the backport queue to contribute them upstream.

## Current Patches

### 1. Grok Empty Response Fix

**Problem:** Grok-4 and other reasoning models sometimes return empty responses with reasoning tokens but no completion tokens, causing OpenHands to get stuck in `AWAITING_USER_INPUT` state.

**Root Cause:** When reasoning models return:

- `completion_tokens: 0`
- `reasoning_tokens: > 0` (internal reasoning occurred)  
- `content: ''` (empty string)
- No tool calls

OpenHands interprets these as requests for user input, causing the agent to stop unnecessarily.

**Solution:** Model-specific handling that prevents waiting for user input when reasoning models return empty responses.

#### Implementation

**Files Modified:**

1. **`vendor/openhands/openhands/llm/llm.py`** - Added model list:

```python
# Models that may return empty responses while performing internal reasoning
MODELS_WITH_EMPTY_REASONING_RESPONSES = [
    'xai/grok-4',
    'xai/grok-4-latest', 
    'xai/grok-4-0709',
    # Add other reasoning models here if they exhibit similar behavior
]
```

2. **`vendor/openhands/openhands/agenthub/codeact_agent/function_calling.py`** - Modified response handling:

```python
from openhands.llm.llm import MODELS_WITH_EMPTY_REASONING_RESPONSES

# In response_to_actions function:
content = str(assistant_msg.content) if assistant_msg.content else ''

# Check if this is a model that may return empty responses while reasoning
model_name = str(getattr(response, 'model', ''))
is_reasoning_model = any(
    model in model_name for model in MODELS_WITH_EMPTY_REASONING_RESPONSES
)

# Don't wait for response if content is empty and it's a reasoning model
# This prevents getting stuck when reasoning models return empty responses while thinking
wait_for_response = True
if is_reasoning_model and not content:
    wait_for_response = False
elif content:  # For all other models, wait if there's content
    wait_for_response = True
else:  # For non-reasoning models with empty content, still wait (original behavior)
    wait_for_response = True

actions.append(
    MessageAction(
        content=content,
        wait_for_response=wait_for_response,
    )
)
```

#### Testing

**Comprehensive test coverage in `vendor/openhands/tests/unit/test_function_calling.py`:**

- `test_message_action_empty_response_non_grok()` - Preserves original behavior for non-Grok models
- `test_message_action_empty_response_grok()` - New behavior for Grok models with empty content
- `test_message_action_non_empty_response_grok()` - Normal behavior for Grok models with content

**Integration test in main project at `tests/unit/test_openhands_grok_empty_response.py`** - Documents expected behavior and validates the fix is working.

#### Benefits

1. **Targeted Fix**: Only affects specified reasoning models, no risk to other models
2. **Backward Compatible**: Existing behavior preserved for all other models  
3. **Extensible**: Easy to add more models to the list if needed
4. **Well-Tested**: Comprehensive test coverage
5. **Type Safety**: Handles cases where model name might not be a string

### 2. Additional Patches

Based on recent commits, additional patches include:

- **HTML Decoding Removal**: Removed HTML decoding functionality
- **Test Fixes**: Updated test expectations to match current argument parsing behavior
- **Type Safety**: Fixed TypeError when model name is not a string

## Fork Management Strategy

### Maintenance Approach

1. **Upstream Tracking**: We track `upstream/main` and regularly rebase our patches
2. **Patch Queue**: Maintain a queue of patches to backport to upstream OpenHands
3. **Local Testing**: All patches are thoroughly tested in our environment
4. **Incremental Upstreaming**: Work through the backport queue as upstream maintainers review

### Adding New Patches

When adding new patches:

1. **Implement**: Create targeted fixes in `vendor/openhands`
2. **Test**: Add comprehensive tests for the changes
3. **Document**: Update this document with patch details
4. **Queue**: Add to backport queue for upstream contribution

### Testing Patches

#### In OpenHands Environment

```bash
cd vendor/openhands
poetry install --with dev,test
poetry run pytest tests/unit/test_function_calling.py -xvs
```

#### In Main Project  

```bash
# Run integration tests that validate patches are working
pytest tests/unit/test_openhands_grok_empty_response.py -xvs
```

### Upstream Contribution

We plan to contribute these patches back to OpenHands:

1. **Empty Response Fix**: Well-tested and ready for upstream PR
2. **Type Safety Fixes**: Generally applicable improvements
3. **Test Updates**: Align with current behavior expectations

## Development Workflow

1. **Feature Development**: Work in main project, test against vendored OpenHands
2. **Patch Development**: Implement fixes directly in `vendor/openhands`
3. **Testing**: Validate both in OpenHands environment and main project integration
4. **Documentation**: Update this document for each new patch
5. **Upstream Planning**: Prepare patches for upstream contribution

## Future Considerations

- Monitor if other reasoning models (o1, o3, etc.) exhibit similar empty response behavior
- Consider generalizing fixes to benefit the broader OpenHands community
- Track upstream changes that might conflict with our patches
- Maintain compatibility as OpenHands evolves

## Directory Structure

```
vendor/openhands/           # Vendored OpenHands fork
├── openhands/llm/llm.py   # Model configurations and lists
├── openhands/agenthub/codeact_agent/function_calling.py  # Core fix
└── tests/unit/test_function_calling.py  # Patch tests

tests/unit/test_openhands_grok_empty_response.py  # Integration test
```

This approach allows us to move quickly with necessary fixes while contributing back to the OpenHands ecosystem.
