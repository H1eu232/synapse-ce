// Package messageformat turns rendered message content, a notification or a ticket body, into each
// destination's wire format (EPIC #1327 D5, step 3). The notification formatters implement
// ports.NotificationFormatter, so delivery and the API preview produce the same bytes; ticketing
// uses the Jira renderers.
//
// Every formatter starts from the same syntax tree, msgmarkdown.Parse of the rendered fields, and
// never passes content through a channel's own markup parser as a string. Where a channel offers a
// structured form that shows text literally, the formatter uses it (Slack rich_text, email HTML
// with every text node escaped); a value can therefore not become a mention, a link or formatting
// in any channel, whatever characters it holds.
//
// Links come only from ports.RenderedMessage.Links, are checked to be absolute https URLs without
// credentials, and are placed by the formatter after the content.
package messageformat
