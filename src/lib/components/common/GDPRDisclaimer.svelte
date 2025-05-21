<script>
  import { goto } from '$app/navigation';
</script>
<header class="w-full  bg-white dark:bg-black px-4 sm:px-8 py-3 flex justify-between items-center fixed top-0 left-0 z-50">
  <!-- Logo -->
  <div class="flex items-center space-x-2">
    <img src="/assets/images/emotions/neutru.png" alt="Logo" class="h-12 sm:h-8 w-auto" />
  </div>

  <!-- Buton -->
  <div>
    <button
      on:click={() => goto('/')}
      class="inline-block px-4 py-2 text-sm font-semibold text-white bg-black dark:bg-white dark:text-black rounded-md hover:bg-gray-900 dark:hover:bg-gray-200 transition"
    >
      Încearcă aplicația
    </button>
  </div>
</header>

<main class="enable_scroll_bar max-w-4xl mx-auto px-4 py-10 text-gray-800 dark:text-gray-100 font-sans">
  <h1 class="text-3xl sm:text-3xl font-bold text-center mb-4">
    ACORD PRIVIND PRELUCRAREA DATELOR CU CARACTER PERSONAL (GDPR)
  </h1>
  <p class="text-center text-gray-600 dark:text-gray-300 mb-12 text-lg font-medium">
    Pentru aplicația de simulare anti-bullying dezvoltată pentru Salvați Copiii România
  </p>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">1. INTRODUCERE</h2>
    <p>
      Prezentul acord descrie modul în care sunt colectate, utilizate și protejate datele cu caracter personal în cadrul aplicației noastre de simulare, dezvoltată în colaborare cu Organizația Salvați Copiii România.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">2. CINE SUNTEM</h2>
    <p>
      Aplicația este dezvoltată de <em>[Numele dvs./companiei dvs.]</em> în parteneriat cu Organizația Salvați Copiii România, având sediul în <em>[adresa Salvați Copiii]</em>.
    </p>
    <p>
      Operatorul de date este <em>[Numele dvs./companiei dvs. SAU Salvați Copiii România]</em>, în funcție de cine este responsabil pentru prelucrarea datelor.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">3. CE DATE COLECTĂM</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Adresa de email (prin autentificarea cu contul Google)</li>
      <li>Date de utilizare (interacțiunile cu aplicația, textele introduse, răspunsurile primite)</li>
      <li>Date tehnice (adresa IP, tipul de dispozitiv, browser-ul utilizat)</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">4. SCOPUL PRELUCRĂRII DATELOR</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Furnizarea funcționalității de bază a aplicației de simulare</li>
      <li>Identificarea utilizatorilor prin adresa de email</li>
      <li>Cercetare și statistici privind fenomenul de bullying</li>
      <li>Respectarea obligațiilor legale</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">5. TEMEIUL JURIDIC PENTRU PRELUCRAREA DATELOR</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Consimțământul dvs.</li>
      <li>Interesul legitim al Salvați Copiii România de a combate fenomenul de bullying</li>
      <li>Îndeplinirea unei sarcini care servește unui interes public în domeniul protecției copilului</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">6. CUI TRANSMITEM DATELE DVS.</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Furnizorilor de servicii (OpenAI pentru procesarea limbajului natural)</li>
      <li>StateMesh (furnizorul de servicii cloud unde este găzduită aplicația)</li>
      <li>Organizației Salvați Copiii România</li>
      <li>Autorităților publice, atunci când există o obligație legală</li>
    </ul>
    <p class="mt-2">
      Nu vom transfera datele dvs. în afara Uniunii Europene sau a Spațiului Economic European fără implementarea garanțiilor adecvate.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">7. PERIOADA DE PĂSTRARE A DATELOR</h2>
    <p>
      Datele vor fi păstrate cel mult 30 de zile de la ultima utilizare a aplicației, cu excepțiile legale.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">8. DREPTURILE DVS.</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Dreptul de acces</li>
      <li>Dreptul la rectificare</li>
      <li>Dreptul la ștergere ("dreptul de a fi uitat")</li>
      <li>Dreptul la restricționare</li>
      <li>Dreptul la portabilitate</li>
      <li>Dreptul la opoziție</li>
      <li>Dreptul de retragere a consimțământului</li>
      <li>Dreptul de a depune plângere la ANSPDCP</li>
    </ul>
    <p class="mt-2">Pentru exercitarea acestor drepturi: <em>[adresa dvs. de email]</em></p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">9. MĂSURI DE SECURITATE</h2>
    <ul class="list-disc pl-6 space-y-1">
      <li>Găzduire în infrastructura StateMesh</li>
      <li>Criptarea datelor în tranzit și în repaus</li>
      <li>Autentificare Google</li>
      <li>Acces restricționat pentru personalul autorizat</li>
      <li>Monitorizare și jurnalizare</li>
      <li>Instruirea personalului</li>
      <li>Audituri și testări periodice</li>
    </ul>
    <p class="mt-2">
      Mai multe detalii: <a href="https://docs.statemesh.net/architecture/security" target="_blank" class="text-blue-600 underline">Statemesh Security Documentation</a>
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">10. RESPONSABILUL CU PROTECȚIA DATELOR (DPO)</h2>
    <p>Email: <em>[adresa DPO]</em></p>
    <p>Telefon: <em>[număr]</em></p>
    <p>Adresă: <em>[adresă poștală]</em></p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">11. MODIFICĂRI ALE POLITICII</h2>
    <p>
      Modificările vor fi afișate în aplicație. Dacă sunt semnificative, veți fi notificat.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">12. COOKIE-URI ȘI TEHNOLOGII SIMILARE</h2>
    <p>
      Aplicația poate folosi cookie-uri. Mai multe detalii în Politica privind Cookie-urile.
    </p>
  </section>

  <footer class="text-center text-sm text-gray-400 mt-20 mb-10">
    © 2025 Salvați Copiii România. Toate drepturile rezervate.
  </footer>
</main>

<style>
  html, body {
    overflow-y: auto;
    height: 100vh;
  }
  .enable_scroll_bar{
    overflow-y: auto;
    height: 100vh;
  }
</style>
