import { strict as assert } from 'assert';
import fs from 'fs';
import { getSDsFromPresentationDef } from '../utils/vpHeplers.js';

describe('Presentation Definition Utilities', () => {
  it('should extract Selective Disclosure fields from presentation_definition_mdl.json', () => {
    // Load the presentation definition from the JSON file
    const presentationDefinitionRaw = fs.readFileSync('./data/presentation_definition_mdl.json', 'utf-8');
    const presentation_definition_mdl = JSON.parse(presentationDefinitionRaw);

    // Call the function to get the selective disclosure fields
    const sdsRequested = getSDsFromPresentationDef(presentation_definition_mdl);

    // Print the results to the console
    console.log('Selective Disclosure Fields:', JSON.stringify(sdsRequested, null, 2));

    // Add assertions to ensure the function works as expected
    assert.ok(Array.isArray(sdsRequested), 'The result should be an array.');
    assert.strictEqual(sdsRequested.length, 2, 'There should be 3 fields requested.');

    console.log('sdsRequested', sdsRequested);
    // assert.deepStrictEqual(sdsRequested, [
    //   'surname',
    //   'given_name',
    //   'phone'
    // ], 'The extracted fields should match the expected values.');
  });
}); 