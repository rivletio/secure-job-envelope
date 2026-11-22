/** The refusal for one form field, shown directly under it. Point the input's
 *  `aria-describedby` at `id` (and set `aria-invalid`) so the message is read with the
 *  field. Renders nothing when the field is fine. */
export function FieldError({ id, message }: { id: string; message?: string }) {
  if (!message) return null;
  return (
    <p id={id} className="text-xs font-medium text-danger">
      {message}
    </p>
  );
}
