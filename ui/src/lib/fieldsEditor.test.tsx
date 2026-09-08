import { describe, expect, it } from "vitest";
import { fireEvent, render } from "@solidjs/testing-library";
import { createFieldsStore, FieldsEditor } from "../pages/Firestore";
import { defaultText, FIELD_TYPES } from "./firestoreValue";

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

describe("FieldsEditor rows", () => {
  it("edits the name in place and marks nothing dirty for a name-only change", () => {
    const [fields, setFields] = createFieldsStore([{ name: "a", type: "string", text: "1" }]);
    const { getAllByLabelText, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const name = getAllByLabelText("Field")[0] as HTMLInputElement;
    name.focus();
    name.value = "ab";
    fireEvent.input(name);
    expect(fields[0]?.name).toBe("ab");
    expect(fields[0]?.text).toBe("1");
    expect(fields[0]?.dirty).toBeUndefined();
    expect(document.activeElement).toBe(name);
    unmount();
  });

  it("changing the type resets the value to that type's default and drops the original", () => {
    const [fields, setFields] = createFieldsStore([
      {
        name: "n",
        type: "string",
        text: "hello",
        original: { stringValue: "hello" },
        numberKind: "integer",
      },
    ]);
    const { getAllByLabelText, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const select = getAllByLabelText("Type")[0] as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual([...FIELD_TYPES]);
    expect([...select.options].map((o) => o.textContent)).toEqual([...FIELD_TYPES]);
    select.value = "boolean";
    fireEvent.change(select);
    expect(fields[0]).toMatchObject({
      type: "boolean",
      text: defaultText("boolean"),
      dirty: true,
    });
    expect(fields[0]?.original).toBeUndefined();
    expect(fields[0]?.numberKind).toBeUndefined();
    unmount();
  });

  it("uses a textarea for array and map values and an input for the rest", () => {
    const [fields, setFields] = createFieldsStore([
      { name: "a", type: "array", text: "[]" },
      { name: "m", type: "map", text: "{}" },
      { name: "s", type: "string", text: "" },
      { name: "z", type: "null", text: "" },
    ]);
    const { getAllByLabelText, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    const values = getAllByLabelText("Value") as HTMLElement[];
    expect(values.map((v) => v.tagName)).toEqual(["TEXTAREA", "TEXTAREA", "INPUT", "INPUT"]);
    expect((values[3] as HTMLInputElement).disabled).toBe(true);
    (values[0] as HTMLTextAreaElement).value = '[{"stringValue":"x"}]';
    fireEvent.input(values[0] as HTMLTextAreaElement);
    expect(fields[0]).toMatchObject({ text: '[{"stringValue":"x"}]', dirty: true });
    unmount();
  });

  it("adds a blank string row at the end and disables every control while busy", () => {
    const [fields, setFields] = createFieldsStore([{ name: "a", type: "string", text: "1" }]);
    const { getByTestId, getAllByLabelText, getAllByRole, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    expect(getByTestId("add-field").textContent).toBe("Add field");
    fireEvent.click(getByTestId("add-field"));
    expect(fields.length).toBe(2);
    expect(fields[1]).toEqual({ name: "", type: "string", text: "" });
    expect(getAllByLabelText("Field").length).toBe(2);
    unmount();

    const busy = render(() => <FieldsEditor fields={fields} setFields={setFields} disabled />);
    for (const el of [
      ...busy.getAllByLabelText("Field"),
      ...busy.getAllByLabelText("Type"),
      ...busy.getAllByLabelText("Value"),
      ...busy.getAllByRole("button"),
    ]) {
      expect((el as HTMLInputElement).disabled).toBe(true);
    }
    busy.unmount();
    void getAllByRole;
  });

  it("labels the columns", () => {
    const [fields, setFields] = createFieldsStore([]);
    const { getAllByRole, unmount } = render(() => (
      <FieldsEditor fields={fields} setFields={setFields} />
    ));
    expect(getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Field",
      "Type",
      "Value",
      "",
    ]);
    unmount();
  });
});
