let isSniffing = false;
let intervalId = null;
let show_features=[
    'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
    'Total Fwd Packets', 'Total Backward Packets', 'Flow Duration',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Min', 'Flow IAT Max', 'Fwd Packets/s', 'Prediction'
]
async function fetchPrediction() {
    const res = await fetch('/predict');
    if (res.ok) {
    const result= await res.json();
    const data=result["data"]
    const tableHeaders= document.getElementById("tableHeaders");
    const tableBody = document.getElementById("tableBody");
    if (data.length > 0) {
        tableHeaders.innerHTML = '';
        show_features.forEach(key => {
          const th = document.createElement("th");
          th.textContent = key;
          tableHeaders.appendChild(th);
        });
        tableBody.innerHTML = '';
        data.forEach(row => {
          const tr = document.createElement("tr");
          show_features.forEach(key => {
            const td = document.createElement("td");
            td.textContent = row[key] 
            tr.appendChild(td);
          });
          tableBody.appendChild(tr);
        });
}
}
const container = document.querySelector(".table-container");
container.scrollTop = container.scrollHeight;
}

async function toggleSniff() {
    isSniffing = !isSniffing;
    const btn = document.getElementById("toggleBtn");

    if (isSniffing) {
    btn.textContent = "Stop";
    btn.classList.add("active"); 
    res=await fetch('/start', { method: 'POST' });
    intervalId = setInterval(fetchPrediction, 1000);  // every second
    } else {
    btn.textContent = "Start";
    btn.classList.remove("active");
    fetch('/stop', { method: 'POST' });
    clearInterval(intervalId);
    }
}