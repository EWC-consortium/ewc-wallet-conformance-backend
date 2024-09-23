
export function getCredentialSubjectForPersona(persona, decodedHeaderSubjectDID) {
  const issuanceDate = new Date(
    Math.floor(Date.now() / 1000) * 1000
  ).toISOString();
  const expiryDate = new Date(
    Math.floor(Date.now() + 60 / 1000) * 1000
  ).toISOString();
 
  const defaultData = {
    id: decodedHeaderSubjectDID,
    issuance_date: issuanceDate,
    expiry_date: expiryDate,
    issuing_authority: "https://aegean.gr",
    age_over_18: true,
  };

  switch (persona) {
    case "1":
      return {
        ...defaultData,
        family_name: "Conti",
        given_name: "Mario",
        birth_date: "1988-11-12",
        issuing_country: "IT",
      };
    case "2":
      return {
        ...defaultData,
        family_name: "Matkalainen",
        given_name: "Hannah",
        birth_date: "2005-02-07",
        issuing_country: "FI",
      };
    case "3":
      return {
        ...defaultData,
        family_name: "Fischer",
        given_name: "Felix",
        birth_date: "1953-01-23",
        issuing_country: "FI",
      };
    default:
      return {
        ...defaultData,
        family_name: "Doe",
        given_name: "John",
        birth_date: "1990-01-01",
        issuing_country: "GR",
      };
  }
}



export function getPersonaFromAccessToken(accessToken, personas, accessTokens) {
    let persona = null;
    for (let i = 0; i < accessTokens.length; i++) {
      console.log(accessTokens[i]);
      if (accessTokens[i] === accessToken) {
        persona = personas[i];
      }
    }
    return persona;
  }