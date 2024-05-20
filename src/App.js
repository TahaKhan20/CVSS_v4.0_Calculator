import React, { useEffect, useState } from 'react';
import './App.css';
import { Metric, cvssConfig, cvssLookup, cvssMacroVectorDetails, cvssMacroVectorValues, maxComposed, maxSeverity } from './cvssDetails';

function App() {
    const [cvssConfigData] = useState(cvssConfig);
    const [maxComposedData] = useState(maxComposed);
    const [maxSeverityData] = useState(maxSeverity);
    const [expectedMetricOrderData] = useState(Metric);
    const [cvssMacroVectorDetailsData] = useState(cvssMacroVectorDetails);
    const [cvssMacroVectorValuesData] = useState(cvssMacroVectorValues);
    const [showDetails, setShowDetails] = useState(false);
    const [cvssSelected, setCvssSelected] = useState({});
    const [lookup] = useState(cvssLookup);

    useEffect(() => {
        resetSelected();
        setButtonsToVector(window.location.hash);

        const handleHashChange = () => {
            setButtonsToVector(window.location.hash);
        };

        window.addEventListener("hashchange", handleHashChange);

        return () => {
            window.removeEventListener("hashchange", handleHashChange);
        };
    }, []);

    const getEQMaxes = (lookup, eq) => {
        return maxComposed["eq" + eq][lookup[eq - 1]];
    };

    const extractValueMetric = (metric, str) => {
        let extracted = str.slice(str.indexOf(metric) + metric.length + 1);
        let metricVal = extracted.indexOf('/') > 0 ? extracted.substring(0, extracted.indexOf('/')) : extracted;
        return metricVal;
    };

    const buttonClass = (isPrimary) => {
        let result = "btn btn-m";
        if (isPrimary) {
            result += " btn-primary";
        }
        return result;
    };

    const scoreClass = (qualScore) => {
        switch (qualScore) {
            case "Low":
                return "c-hand text-green";
            case "Medium":
                return "c-hand text-yellow";
            case "High":
                return "c-hand text-orange";
            case "Critical":
                return "c-hand text-red text-bold";
            default:
                return "c-hand text-black";
        }
    };

    const copyVector = () => {
        navigator.clipboard.writeText(vector());
        window.location.hash = vector();
    };

    const onButton = (metric, value) => {
        setCvssSelected({ ...cvssSelected, [metric]: value });
        window.location.hash = vector();
    };
    const resetSelected = () => {
      const newCvssSelected = {};
      for (const [metricType, metricTypeData] of Object.entries(cvssConfigData)) {
          for (const [metricGroup, metricGroupData] of Object.entries(metricTypeData.metric_groups)) {
              for (const [metric, metricData] of Object.entries(metricGroupData)) {
                  newCvssSelected[metricData.short] = metricData.selected;
              }
          }
      }
      // Update cvssSelected state
      setCvssSelected(newCvssSelected);
  };

  const setButtonsToVector = (vector) => {
      const metrics = vector.split("/");
      metrics.shift();
      let toSelect = {};
      let oi = 0;
      for (let index in metrics) {
          const [key, value] = metrics[index].split(":");

          let expected = Object.entries(expectedMetricOrderData)[oi++];
          while (true) {
              // If out of possible metrics ordering, it's not a valid value thus
              // the vector is invalid
              if (expected === undefined) {
                  console.error("Error invalid vector, too many metric values");
                  return;
              }
              if (key !== expected[0]) {
                  // If not this metric but is mandatory, the vector is invalid
                  // As the only mandatory ones are from the Base group, 11 is the
                  // number of metrics part of it.
                  if (oi <= 11) {
                      console.error("Error invalid vector, missing mandatory metrics");
                      return;
                  }
                  // If a non-mandatory, retry
                  expected = Object.entries(expectedMetricOrderData)[oi++];
                  continue;
              }
              break;
          }
          // The value MUST be part of the metric's values, case insensitive
          if (!expected[1].includes(value)) {
              console.error(`Error invalid vector, for key ${key}, value ${value} is not in ${expected[1]}`);
              return;
          }
          if (key in cvssSelected) {
              toSelect[key] = value;
          }
      }

      for (let key in toSelect) {
          setCvssSelected(prevState => ({
              ...prevState,
              [key]: toSelect[key]
          }));
      }
    }
    const m = (metric) => {
        
        let selected = cvssSelected[metric];
      // If E=X it will default to the worst case i.e. E=A
      if (metric === "E" && selected === "X") {
          return "A";
      }
      // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
      if (metric === "CR" && selected === "X") {
          return "H";
      }
      // IR:X is the same as IR:H
      if (metric === "IR" && selected === "X") {
          return "H";
      }
      // AR:X is the same as AR:H
      if (metric === "AR" && selected === "X") {
          return "H";
      }

      // All other environmental metrics just overwrite base score values,
      // so if they’re not defined just use the base score value.
      if (Object.keys(cvssSelected).includes("M" + metric)) {
          let modifiedSelected = cvssSelected["M" + metric];
          if (modifiedSelected !== "X") {
              return modifiedSelected;
          }
      }

      return selected;
    };

    const onReset = () => {
        resetSelected();
        window.location.hash = "";
    };

    
    const splitObjectEntries = (object, chunkSize) => {
        const arr = Object.entries(object);
        const res = [];
        for (let i = 0; i < arr.length; i += chunkSize) {
            const chunk = arr.slice(i, i + chunkSize);
            res.push(chunk);
        }
        return res;
    };

    const vector = () => {
        let value = "";
        for (const metric in expectedMetricOrderData) {
            const selected = cvssSelected[metric];
            if (selected !== "X") {
                value = value.concat(`/`+`${metric}:${selected}`);
            }
        }
        return value;
    };
    
    const macroVector = () => {
        let eq1, eq2, eq3, eq4, eq5, eq6;
        
        // EQ1
        if (m("AV") === "N" && m("PR") === "N" && m("UI") === "N") {
            eq1 = "0";
        } else if ((m("AV") === "N" || m("PR") === "N" || m("UI") === "N") && !(m("AV") === "N" && m("PR") === "N" && m("UI") === "N") && !(m("AV") === "P")) {
            eq1 = "1";
        } else if (m("AV") === "P" || !(m("AV") === "N" || m("PR") === "N" || m("UI") === "N")) {
            eq1 = "2";
        }

        // EQ2
        if (m("AC") === "L" && m("AT") === "N") {
            eq2 = "0";
        } else if (!(m("AC") === "L" && m("AT") === "N")) {
            eq2 = "1";
        }

        // EQ3
        if (m("VC") === "H" && m("VI") === "H") {
            eq3 = "0";
        } else if (!(m("VC") === "H" && m("VI") === "H") && (m("VC") === "H" || m("VI") === "H" || m("VA") === "H")) {
            eq3 = "1";
        } else if (!(m("VC") === "H" || m("VI") === "H" || m("VA") === "H")) {
            eq3 = "2";
        }

        // EQ4
        if (m("MSI") === "S" || m("MSA") === "S") {
            eq4 = "0";
        } else if (!(m("MSI") === "S" || m("MSA") === "S") && (m("SC") === "H" || m("SI") === "H" || m("SA") === "H")) {
            eq4 = "1";
        } else if (!(m("MSI") === "S" || m("MSA") === "S") && !((m("SC") === "H" || m("SI") === "H" || m("SA") === "H"))) {
            eq4 = "2";
        }

        // EQ5
        if (m("E") === "A") {
            eq5 = "0";
        } else if (m("E") === "P") {
            eq5 = "1";
        } else{
            eq5 = "2";
        }

        // EQ6
        if ((m("CR") === "H" && m("VC") === "H") || (m("IR") === "H" && m("VI") === "H") || (m("AR") === "H" && m("VA") === "H")) {
            eq6 = "0";
        } else if (!((m("CR") === "H" && m("VC") === "H") || (m("IR") === "H" && m("VI") === "H") || (m("AR") === "H" && m("VA") === "H"))) {
            eq6 = "1";
        }
        return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
    };

    const score = () => {
        // Define levels for each metric
        const AV_levels = { "N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3 };
        const PR_levels = { "N": 0.0, "L": 0.1, "H": 0.2 };
        const UI_levels = { "N": 0.0, "P": 0.1, "A": 0.2 };
        const AC_levels = { 'L': 0.0, 'H': 0.1 };
        const AT_levels = { 'N': 0.0, 'P': 0.1 };
        const VC_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 };
        const VI_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 };
        const VA_levels = { 'H': 0.0, 'L': 0.1, 'N': 0.2 };
        const SC_levels = { 'H': 0.1, 'L': 0.2, 'N': 0.3 };
        const SI_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 };
        const SA_levels = { 'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3 };
        const CR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 };
        const IR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 };
        const AR_levels = { 'H': 0.0, 'M': 0.1, 'L': 0.2 };
        const E_levels = { 'U': 0.2, 'P': 0.1, 'A': 0 };

        
        // Exception for no impact on the system
        if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m(metric) === "N")) {
            return 0.0;
        }

        // Retrieve the score of the current macroVector
        let value = lookup[macroVector()];
        // Compute the maximal scoring difference for each EQ
        const eq1_val = parseInt(macroVector()[0]);
        const eq2_val = parseInt(macroVector()[1]);
        const eq3_val = parseInt(macroVector()[2]);
        const eq4_val = parseInt(macroVector()[3]);
        const eq5_val = parseInt(macroVector()[4]);
        const eq6_val = parseInt(macroVector()[5]);
        
        // Compute next lower macroVector (if exists)
        let eq1_next_lower_macro = `${eq1_val + 1}${eq2_val}${eq3_val}${eq4_val}${eq5_val}${eq6_val}`;
        let eq2_next_lower_macro = `${eq1_val}${eq2_val + 1}${eq3_val}${eq4_val}${eq5_val}${eq6_val}`;
        let eq3eq6_next_lower_macro = "";
        
        if (eq3_val === 0 && eq6_val === 0) {
            eq3eq6_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val}${eq4_val}${eq5_val}${eq6_val + 1}`;
        } else if (eq3_val === 1 && eq6_val === 0) {
            eq3eq6_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val}${eq4_val}${eq5_val}${eq6_val + 1}`;
        } else if (eq3_val === 0 && eq6_val === 1) {
            eq3eq6_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val + 1}${eq4_val}${eq5_val}${eq6_val}`;
        } else if (eq3_val === 1 && eq6_val === 1) {
            eq3eq6_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val + 1}${eq4_val}${eq5_val}${eq6_val + 1}`;
        }
        
        let eq4_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val}${eq4_val + 1}${eq5_val}${eq6_val}`;
        let eq5_next_lower_macro = `${eq1_val}${eq2_val}${eq3_val}${eq4_val}${eq5_val + 1}${eq6_val}`;
        
        // Get scores for next lower macroVectors
        let score_eq1_next_lower_macro = lookup[eq1_next_lower_macro];
        let score_eq2_next_lower_macro = lookup[eq2_next_lower_macro];
        let score_eq3eq6_next_lower_macro = lookup[eq3eq6_next_lower_macro];
        let score_eq4_next_lower_macro = lookup[eq4_next_lower_macro];
        let score_eq5_next_lower_macro = lookup[eq5_next_lower_macro];
        console.log("score_eq1_next_lower_macro:", score_eq1_next_lower_macro);
console.log("score_eq2_next_lower_macro:", score_eq2_next_lower_macro);
console.log("score_eq3eq6_next_lower_macro:", score_eq3eq6_next_lower_macro);
console.log("score_eq4_next_lower_macro:", score_eq4_next_lower_macro);
console.log("score_eq5_next_lower_macro:", score_eq5_next_lower_macro);

        // Get maxes for each EQ
        const eq1_maxes = getEQMaxes(macroVector(), 1);
        const eq2_maxes = getEQMaxes(macroVector(), 2);
        const eq3_eq6_maxes = getEQMaxes(macroVector(), 3)[macroVector()[5]];
        const eq4_maxes = getEQMaxes(macroVector(), 4);
        const eq5_maxes = getEQMaxes(macroVector(), 5);
        
        // if any is less than zero this is not the right max
        let max_vector = "";

        // Find the max vector to use
        const max_vectors = [];
        for (const eq1_max of eq1_maxes) {
            for (const eq2_max of eq2_maxes) {
                for (const eq3_eq6_max of eq3_eq6_maxes) {
                    for (const eq4_max of eq4_maxes) {
                        for (const eq5max of eq5_maxes) {
                            max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max);
                        }
                    }
                }
            }
        }
        console.log(max_vectors)
        let severity_distance_AV;
        let severity_distance_PR;
        let severity_distance_UI;
        let severity_distance_AC;
        let severity_distance_AT;
        let severity_distance_VC;
        let severity_distance_VI;
        let severity_distance_VA;
        let severity_distance_SC;
        let severity_distance_SI;
        let severity_distance_SA;
        let severity_distance_CR;
        let severity_distance_IR;
        let severity_distance_AR;
        // Loop through max vectors to find the suitable one
        for (let i = 0; i < max_vectors.length; i++) {
            max_vector = max_vectors[i];

            // Compute severity distances again
            severity_distance_AV = parseFloat((AV_levels[m("AV")] - AV_levels[extractValueMetric("AV", max_vector)]).toFixed(1));
            severity_distance_PR = parseFloat((PR_levels[m("PR")] - PR_levels[extractValueMetric("PR", max_vector)]).toFixed(1));
            severity_distance_UI = parseFloat((UI_levels[m("UI")] - UI_levels[extractValueMetric("UI", max_vector)]).toFixed(1));
            severity_distance_AC = parseFloat((AC_levels[m("AC")] - AC_levels[extractValueMetric("AC", max_vector)]).toFixed(1));
            severity_distance_AT = parseFloat((AT_levels[m("AT")] - AT_levels[extractValueMetric("AT", max_vector)]).toFixed(1));
            severity_distance_VC = parseFloat((VC_levels[m("VC")] - VC_levels[extractValueMetric("VC", max_vector)]).toFixed(1));
            severity_distance_VI = parseFloat((VI_levels[m("VI")] - VI_levels[extractValueMetric("VI", max_vector)]).toFixed(1));
            severity_distance_VA = parseFloat((VA_levels[m("VA")] - VA_levels[extractValueMetric("VA", max_vector)]).toFixed(1));
            severity_distance_SC = parseFloat((SC_levels[m("SC")] - SC_levels[extractValueMetric("SC", max_vector)]).toFixed(1));
            severity_distance_SI = parseFloat((SI_levels[m("SI")] - SI_levels[extractValueMetric("SI", max_vector)]).toFixed(1));
            severity_distance_SA = parseFloat((SA_levels[m("SA")] - SA_levels[extractValueMetric("SA", max_vector)]).toFixed(1));
            severity_distance_CR = parseFloat((CR_levels[m("CR")] - CR_levels[extractValueMetric("CR", max_vector)]).toFixed(1));
            severity_distance_IR = parseFloat((IR_levels[m("IR")] - IR_levels[extractValueMetric("IR", max_vector)]).toFixed(1));
            severity_distance_AR = parseFloat((AR_levels[m("AR")] - AR_levels[extractValueMetric("AR", max_vector)]).toFixed(1));
            
            // if any is less than zero this is not the right max
            if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) {
                continue;
            }
            // if multiple maxes exist to reach it it is enough the first one
            break;
        }
        
        const current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI;
        const current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT;
        const current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR;
        const current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA;
        
        const step = 0.1;

        let available_distance_eq1 = value - score_eq1_next_lower_macro;
        let available_distance_eq2 = value - score_eq2_next_lower_macro;
        let available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro;
        let available_distance_eq4 = value - score_eq4_next_lower_macro;
        let available_distance_eq5 = value - score_eq5_next_lower_macro;
        
        let percent_to_next_eq1_severity = 0;
        let percent_to_next_eq2_severity = 0;
        let percent_to_next_eq3eq6_severity = 0;
        let percent_to_next_eq4_severity = 0;
        let percent_to_next_eq5_severity = 0;
        
        let n_existing_lower = 0;
        
        let normalized_severity_eq1 = 0;
        let normalized_severity_eq2 = 0;
        let normalized_severity_eq3eq6 = 0;
        let normalized_severity_eq4 = 0;
        let normalized_severity_eq5 = 0;
        
        const maxSeverity_eq1 = maxSeverityData["eq1"][eq1_val] * step;
        const maxSeverity_eq2 = maxSeverityData["eq2"][eq2_val] * step;
        const maxSeverity_eq3eq6 = maxSeverityData["eq3eq6"][eq3_val][eq6_val] * step;
        const maxSeverity_eq4 = maxSeverityData["eq4"][eq4_val] * step;
        
        if (!isNaN(available_distance_eq1)) {
            n_existing_lower++;
            percent_to_next_eq1_severity = (current_severity_distance_eq1) / maxSeverity_eq1;
            normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity;
        }
        
        if (!isNaN(available_distance_eq2)) {
            n_existing_lower++;
            percent_to_next_eq2_severity = (current_severity_distance_eq2) / maxSeverity_eq2;
            normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity;
        }
        
        if (!isNaN(available_distance_eq3eq6)) {
            n_existing_lower++;
            percent_to_next_eq3eq6_severity = (current_severity_distance_eq3eq6) / maxSeverity_eq3eq6;
            normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity;
        }
        
        if (!isNaN(available_distance_eq4)) {
            n_existing_lower++;
            percent_to_next_eq4_severity = (current_severity_distance_eq4) / maxSeverity_eq4;
            normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity;
        }
        
        if (!isNaN(available_distance_eq5)) {
            n_existing_lower++;
            percent_to_next_eq5_severity = 0;
            normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity;
        }
        
        let mean_distance = 0;
        if (n_existing_lower !== 0) {
            mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower;
        }
        
        value -= mean_distance;
        value = parseFloat(value.toFixed(1));
        if (value < 0) {
            value = 0;
        }
        if(value > 10){
            value = 10;
        }
        return value;
    };

    const qualScore = (score) => {
        if (score === 0.0) {
            return "None";
        } else if (score < 4.0) {
            return "Low";
        } else if (score < 7.0) {
            return "Medium";
        } else if (score < 9.0) {
            return "High";
        } else {
            return "Critical";
        }
    };

    return (
                <div id="app" className="container">
                    <div id="header">
                        <img alt="CVSS logo" src="https://first.org/cvss/identity/cvssv4_web.png" width="150" />
                        <h3 className="page-title"></h3>
                        <mark className="tooltip c-hand" data-tooltip="Click vector to copy to clipboard" onClick={copyVector}>
                            {vector()}
                        </mark>
                        <button style={{ width: '70px', height:'35px',fontSize:'80%', borderRadius:'30px', border:'1px solid transparent' }} onClick={onReset}>Reset</button>
                        <h5 className="score-line">
                            <span className="tooltip tooltip-bottom c-hand"
                                data-tooltip={showDetails ? 'Hide details' : 'Show details'}
                                onClick={() => setShowDetails(!showDetails)}>
                                CVSS v4.0 Score:
                                <span className={scoreClass(qualScore(score()))}> {score()} / {qualScore(score())}</span>
                                <span>{showDetails ? ' ⊖' : ' ⊕'}</span>
                            </span>
                        </h5>
                        {showDetails && (
                            <blockquote>
                                <sup className="mb-2"><h5>Macro vector: {macroVector()}</h5></sup>
                                <div>
                                    {Object.entries(cvssMacroVectorDetailsData).map(([index, description]) => (
                                        <div key={index}>
                                            {description}: {cvssMacroVectorValuesData[macroVector()[index]]}
                                        </div>
                                    ))}
                                </div>
                            </blockquote>
                        )}
                    </div>

                    <div className="columns">
                        <h6 id="cvssReference" style={{ width: '100%', maxWidth: '1065px', margin: '10px' }}> </h6>
                        <div className="column cols col-xl-12">
                            {Object.entries(cvssConfigData).map(([metricType, metricTypeData]) => (
                                <div className="metric-type" key={metricType}>
                                    <h4 className="text-center">
                                        {metricType}
                                        <span className="tooltip tooltip-left c-hand text-small" data-tooltip={`This category is usually filled by the ${metricTypeData.fill}`}>
                                            
                                        </span>
                                    </h4>

                                    {Object.entries(metricTypeData.metric_groups).map(([metricGroup, metricGroupData]) => (
                                        <div className="metric-group" key={metricGroup}>
                                            <h5 className="text-center">{metricGroup}</h5>
                                            <div>
                                                {Object.entries(metricGroupData).map(([metric, metricData]) => (
                                                    <div key={metric}>
                                                        <div className="columns">
                                                            <div className="col" style={{ visibility: metricData.tooltip ? 'visible' : 'hidden' }}>
                                                                <abbr title={metricData.tooltip}>{metric}</abbr>:
                                                            </div>
                                                            <div className="cols columns">
                                                                {Object.entries(metricData.options).map(([option, optionData]) => (
                                                                    <div className="options" key={option} style={{ visibility: optionData.tooltip ? 'visible' : 'hidden' }}>
                                                                        <button className={buttonClass(cvssSelected && metricData && cvssSelected[metricData.short] === optionData.value)} onClick={() => onButton(metricData && metricData.short, optionData && optionData.value)}>
                                                                            <abbr title={optionData.tooltip}>{option}</abbr>
                                                                        </button>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
    );
}

export default App;
