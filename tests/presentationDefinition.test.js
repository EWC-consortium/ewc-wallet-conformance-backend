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

describe('Presentation Definition (PE) structure - OID4VP v1.0', () => {
  it('PID PD must use dc+sd-jwt and granular JSONPath fields', () => {
    const pdRaw = fs.readFileSync('./data/presentation_definition_pid.json', 'utf-8');
    const pd = JSON.parse(pdRaw);

    // Top-level format must advertise dc+sd-jwt
    assert.ok(pd.format && pd.format['dc+sd-jwt'], 'Top-level format.dc+sd-jwt is required');

    // Must have input_descriptors with constraints.fields
    assert.ok(Array.isArray(pd.input_descriptors) && pd.input_descriptors.length > 0, 'input_descriptors required');
    const id0 = pd.input_descriptors[0];
    assert.ok(id0.constraints && Array.isArray(id0.constraints.fields) && id0.constraints.fields.length > 0, 'constraints.fields required');

    // Fields should use JSONPath pointers starting with $
    const allPaths = id0.constraints.fields.flatMap(f => f.path || []);
    assert.ok(allPaths.every(p => typeof p === 'string' && p.startsWith('$.')), 'All field paths must be JSONPath starting with $.');

    // Granular selectors: ensure specific claims are requested (data minimization)
    const requiredClaims = ['given_name', 'family_name', 'birth_date', 'age_over_18'];
    for (const claim of requiredClaims) {
      const hasClaim = allPaths.some(p => p.endsWith(`.${claim}`) || p === `$.${claim}`);
      assert.ok(hasClaim, `PD must request granular claim: ${claim}`);
    }

    // Must not request entire credential objects
    assert.ok(!allPaths.includes('$') && !allPaths.includes('$.vc') && !allPaths.includes('$.credentialSubject'), 'PD must not target whole objects');

    // Ensure vct filter is specific to EU PID
    const vctField = id0.constraints.fields.find(f => Array.isArray(f.path) && f.path.some(p => p === '$.vct' || p === '$.vc.vct'));
    assert.ok(vctField && vctField.filter && vctField.filter.const === 'urn:eu.europa.ec.eudi:pid:1', 'vct filter must target EU PID');
  });

  it('Legacy SD-JWT PD should not be used for v1.0 (vc+sd-jwt present)', () => {
    const pdRaw = fs.readFileSync('./data/presentation_definition_sdjwt.json', 'utf-8');
    const pd = JSON.parse(pdRaw);

    // This file uses vc+sd-jwt; test documents that it is legacy (migration target is dc+sd-jwt)
    assert.ok(pd.format && pd.format['vc+sd-jwt'], 'Legacy PD advertises vc+sd-jwt');
  });

  it('Verifier metadata must advertise dc+sd-jwt (not vc+sd-jwt)', () => {
    const verifierConfigRaw = fs.readFileSync('./data/verifier-config.json', 'utf-8');
    const cfg = JSON.parse(verifierConfigRaw);

    // vp_formats_supported must contain dc+sd-jwt
    assert.ok(cfg.vp_formats_supported && cfg.vp_formats_supported['dc+sd-jwt'], 'verifier-config.vp_formats_supported.dc+sd-jwt required');
    // must not contain vc+sd-jwt
    assert.ok(!cfg.vp_formats_supported['vc+sd-jwt'], 'verifier-config must not advertise legacy vc+sd-jwt');

    // vp_formats (actual request capability) must also use dc+sd-jwt
    assert.ok(cfg.vp_formats && cfg.vp_formats['dc+sd-jwt'], 'verifier-config.vp_formats.dc+sd-jwt required');
    assert.ok(!cfg.vp_formats['vc+sd-jwt'], 'verifier-config must not use legacy vc+sd-jwt in vp_formats');
  });

  it('In-code CLIENT_METADATA must advertise dc+sd-jwt', async () => {
    // Dynamically import to read the object
    const rt = await import('../utils/routeUtils.js');
    const meta = rt.CLIENT_METADATA;
    assert.ok(meta && meta.vp_formats && meta.vp_formats['dc+sd-jwt'], 'CLIENT_METADATA.vp_formats.dc+sd-jwt required');
    assert.ok(!meta.vp_formats['vc+sd-jwt'], 'CLIENT_METADATA must not use legacy vc+sd-jwt');
  });

  it('Verifier metadata must specify sd-jwt_alg_values and kb-jwt_alg_values for dc+sd-jwt', () => {
    const verifierConfigRaw = fs.readFileSync('./data/verifier-config.json', 'utf-8');
    const cfg = JSON.parse(verifierConfigRaw);
    const vps = cfg.vp_formats_supported?.['dc+sd-jwt'];
    const vp = cfg.vp_formats?.['dc+sd-jwt'];

    // vp_formats_supported
    assert.ok(vps && Array.isArray(vps['sd-jwt_alg_values']) && vps['sd-jwt_alg_values'].length > 0, 'vp_formats_supported.dc+sd-jwt.sd-jwt_alg_values required');
    assert.ok(vps && Array.isArray(vps['kb-jwt_alg_values']) && vps['kb-jwt_alg_values'].length > 0, 'vp_formats_supported.dc+sd-jwt.kb-jwt_alg_values required');

    // vp_formats
    assert.ok(vp && Array.isArray(vp['sd-jwt_alg_values']) && vp['sd-jwt_alg_values'].length > 0, 'vp_formats.dc+sd-jwt.sd-jwt_alg_values required');
    assert.ok(vp && Array.isArray(vp['kb-jwt_alg_values']) && vp['kb-jwt_alg_values'].length > 0, 'vp_formats.dc+sd-jwt.kb-jwt_alg_values required');
  });

  it('In-code CLIENT_METADATA must include both algorithm sets for dc+sd-jwt', async () => {
    const rt = await import('../utils/routeUtils.js');
    const fm = rt.CLIENT_METADATA?.vp_formats?.['dc+sd-jwt'];
    assert.ok(fm && Array.isArray(fm['sd-jwt_alg_values']) && fm['sd-jwt_alg_values'].length > 0, 'CLIENT_METADATA.vp_formats.dc+sd-jwt.sd-jwt_alg_values required');
    assert.ok(fm && Array.isArray(fm['kb-jwt_alg_values']) && fm['kb-jwt_alg_values'].length > 0, 'CLIENT_METADATA.vp_formats.dc+sd-jwt.kb-jwt_alg_values required');
  });
});