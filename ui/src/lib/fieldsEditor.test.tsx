import { describe, expect, it } from "vitest";
import { fireEvent, render } from "@solidjs/testing-library";
import { createFieldsStore, FieldsEditor } from "../pages/Firestore";

// Typing must edit the input in place. The editor once rebuilt the whole row on every
// keystroke (a new row object per change), which dropped focus, the caret position and any
// IME composition after the first character.
describe("FieldsEditor keeps the focused input across keystrokes", () => {
  it("types one character at a time into the same element without losing focus", () => {
    const [fields, setFields] = createFieldsStore([{ name: "", type: "string", text: "" }]);
    const { getAllByLabelText, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const input = getAllByLabelText("Value")[0] as HTMLInputElement;
    input.focus();
    for (const [i, ch] of [..."hello"].entries()) {
      input.value = "hello".slice(0, i + 1);
      fireEvent.input(input);
      expect(document.activeElement).toBe(input);
      expect(getAllByLabelText("Value")[0]).toBe(input);
      expect(fields[0]?.text).toBe("hello".slice(0, i + 1));
      expect(input.value).toBe("hello".slice(0, i + 1));
      expect(ch).toBeDefined();
    }
    expect(fields[0]?.dirty).toBe(true);
    unmount();
  });

  it("inserts in the middle of the value without moving the caret to the end", () => {
    const [fields, setFields] = createFieldsStore([{ name: "n", type: "string", text: "ac" }]);
    const { getAllByLabelText, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const input = getAllByLabelText("Value")[0] as HTMLInputElement;
    input.focus();
    input.setSelectionRange(1, 1);
    input.setRangeText("b", 1, 1, "end");
    fireEvent.input(input);
    expect(fields[0]?.text).toBe("abc");
    expect(document.activeElement).toBe(input);
    expect(input.selectionStart).toBe(2);
    unmount();
  });

  it("removes a row while the others keep their elements", () => {
    const [fields, setFields] = createFieldsStore([
      { name: "a", type: "string", text: "1" },
      { name: "b", type: "string", text: "2" },
    ]);
    const { getAllByLabelText, getAllByRole, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const second = getAllByLabelText("Field")[1];
    fireEvent.click(getAllByRole("button", { name: "Delete" })[0] as HTMLElement);
    expect(fields.length).toBe(1);
    expect(getAllByLabelText("Field")[0]).toBe(second);
    unmount();
  });
});
