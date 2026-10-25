document.addEventListener("DOMContentLoaded", function () {
  const inputs = document.querySelectorAll(".otp-input");
  const form = document.getElementById("otp-form");
  const fullCodeInput = document.getElementById("full-code");
  const otpSection = document.getElementById("otp-section");
  const verifyingSection = document.getElementById("verifying-section");
  const percentText = document.getElementById("verify-percent");

  // Auto focus next/previous input
  inputs.forEach((input, index) => {
    input.addEventListener("input", (e) => {
      if (e.target.value.length === 1 && index < inputs.length - 1) {
        inputs[index + 1].focus();
      }
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !input.value && index > 0) {
        inputs[index - 1].focus();
      }
    });
  });

  // Handle Form Submit & Animation
  form.addEventListener("submit", function (e) {
    e.preventDefault();

    // Combine code
    let code = "";
    inputs.forEach(input => code += input.value);
    fullCodeInput.value = code;

    // Show Verifying Animation
    otpSection.classList.add("d-none");
    verifyingSection.classList.remove("d-none");

    // Percentage counter (0 to 100%)
    let count = 0;
    const interval = setInterval(() => {
      count += Math.floor(Math.random() * 12) + 5;
      if (count >= 100) {
        count = 100;
        clearInterval(interval);
        setTimeout(() => {
          form.submit(); // Actual Flask Form Submit
        }, 300);
      }
      percentText.textContent = count + "%";
    }, 120);
  });
});