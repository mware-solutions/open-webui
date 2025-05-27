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

<main class="enable_scroll_bar max-w-4xl mx-auto px-4 pb-10 text-gray-800 dark:text-gray-100 font-sans">
  <h1 class="text-3xl sm:text-3xl font-bold text-center mb-4">
    ACORD PRIVIND PRELUCRAREA DATELOR CU CARACTER PERSONAL (GDPR)
  </h1>
  <p class="text-center text-gray-600 dark:text-gray-300 mb-12 text-lg font-medium">
    Pentru aplicația de simulare anti-bullying dezvoltată pentru Salvați Copiii România
  </p>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">1. INTRODUCERE</h2>
    <p>
      Prezentul acord descrie modul în care sunt colectate, utilizate și protejate datele cu caracter personal în cadrul aplicației noastre de simulare, dezvoltată ca proiect pro-bono pentru Organizația Salvați Copiii România.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">2. CINE SUNTEM</h2>
    <p>
      Aplicația este dezvoltată de MWARE SOLUTIONS S.A. ca proiect pro-bono pentru Organizația Salvați Copiii România.
    </p>
    <p>
      Operatorul de date este MWARE SOLUTIONS S.A.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">3. CE DATE COLECTĂM</h2>
    <p>În cadrul utilizării aplicației noastre, colectăm următoarele date:</p>
    <ul class="list-disc pl-6 space-y-1">
      <li>Adresa de email (prin autentificarea cu contul Google)</li>
      <li>Date de utilizare (interacțiunile cu aplicația, textele introduse, răspunsurile primite)</li>
      <li>Date tehnice (adresa IP, tipul de dispozitiv, browser-ul utilizat)</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">4. SCOPUL PRELUCRĂRII DATELOR</h2>
    <p>Datele dvs. sunt prelucrate în următoarele scopuri:</p>
    <ul class="list-disc pl-6 space-y-1">
      <li>Furnizarea funcționalității de bază a aplicației de simulare</li>
      <li>Identificarea utilizatorilor prin adresa de email</li>
      <li>Cercetare și statistici privind fenomenul de bullying</li>
      <li>Respectarea obligațiilor legale</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">5. TEMEIUL JURIDIC PENTRU PRELUCRAREA DATELOR</h2>
    <p>Prelucrăm datele dvs. pe baza următoarelor temeiuri juridice:</p>
    <ul class="list-disc pl-6 space-y-1">
      <li>Consimțământul dvs.</li>
      <li>Interesul legitim al Salvați Copiii România de a combate fenomenul de bullying</li>
      <li>Îndeplinirea unei sarcini care servește unui interes public în domeniul protecției copilului</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">6. CUI TRANSMITEM DATELE DVS.</h2>
    <p>Datele dvs. pot fi transmise următoarelor categorii de destinatari:</p>
    <ul class="list-disc pl-6 space-y-1">
      <li>Furnizorilor de servicii (OpenAI pentru procesarea limbajului natural)</li>
      <li>StateMesh (furnizorul de servicii cloud unde este găzduită aplicația)</li>
      <li>Organizației Salvați Copiii România</li>
      <li>Autorităților publice, atunci când există o obligație legală</li>
    </ul>
    <p class="mt-2">
      Nu vom transfera datele dvs. în afara Uniunii Europene sau a Spațiului Economic European fără implementarea garanțiilor adecvate de protecție a datelor.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">7. DREPTURILE DVS.</h2>
    <p> În conformitate cu prevederile GDPR, beneficiați de următoarele drepturi:</p>
    <ul class="list-disc pl-6 space-y-1">
      <li>Dreptul de acces la datele dvs.</li>
      <li>Dreptul la rectificarea datelor inexacte</li>
      <li>Dreptul la ștergerea datelor ("dreptul de a fi uitat")</li>
      <li>Dreptul la restricționarea prelucrării</li>
      <li>Dreptul la portabilitatea datelor</li>
      <li>Dreptul la opoziție</li>
      <li>Dreptul de a vă retrage consimțământul în orice moment</li>
      <li>Dreptul de a depune o plângere la Autoritatea Națională de Supraveghere a Prelucrării Datelor cu Caracter Personal (ANSPDCP)</li>
    </ul>
    <p class="mt-2">
      Pentru a vă exercita aceste drepturi, vă rugăm să ne contactați la <a href="mailto:flavius.burca@m-ware.eu" class="text-blue-600 underline hover:text-blue-800">flavius.burca@m-ware.eu</a>.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">8. MĂSURI DE SECURITATE</h2>
    <p>
      Aplicația noastră este găzduită în infrastructura cloud furnizată de StateMesh și beneficiază de măsurile de securitate implementate de această platformă, conform documentației lor de securitate disponibilă la
      <a href="https://docs.statemesh.net/architecture/security" target="_blank" class="text-blue-600 underline">docs.statemesh.net</a>.
    </p>
    <p>Suplimentar, am implementat următoarele măsuri tehnice și organizatorice pentru a asigura un nivel adecvat de protecție a datelor dvs.:</p>
    <ul class="list-disc pl-6 space-y-1 mt-2">
      <li>Criptarea datelor în tranzit și în repaus</li>
      <li>Autentificare securizată prin Google</li>
      <li>Accesul restricționat la date pentru personalul autorizat</li>
      <li>Monitorizarea și jurnalizarea accesului la date</li>
      <li>Instruirea periodică a personalului care prelucrează datele dvs.</li>
      <li>Evaluări periodice ale vulnerabilităților și testări de securitate</li>
    </ul>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">9. CONTACT PENTRU ÎNTREBĂRI PRIVIND PROTECȚIA DATELOR</h2>
    <p>Pentru orice întrebări legate de prelucrarea datelor dvs. cu caracter personal sau pentru exercitarea drepturilor dvs., ne puteți contacta la:</p>
    <p>Email: <a href="mailto:flavius.burca@m-ware.eu" class="text-blue-600 underline hover:text-blue-800">flavius.burca@m-ware.eu</a></p>
    <p>Telefon: 0727399091</p>
    <p>Adresă: București, Sectorul 2, Șos. Pipera Nr. 43, Floreasca Park, Clădirea B, Etaj 1</p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">10. MODIFICĂRI ALE POLITICII DE CONFIDENȚIALITATE</h2>
    <p>
      Ne rezervăm dreptul de a modifica prezenta politică de confidențialitate. Orice modificări vor fi publicate în cadrul aplicației și, dacă acestea sunt semnificative, vă vom notifica direct.
    </p>
  </section>

  <section class="mb-10">
    <h2 class="text-2xl font-semibold mb-2">11. COOKIE-URI ȘI TEHNOLOGII SIMILARE</h2>
    <p>
      Aplicația noastră poate utiliza cookie-uri și tehnologii similare pentru a îmbunătăți experiența utilizatorului. Puteți găsi mai multe informații despre cookie-urile utilizate și opțiunile de gestionare a acestora în Politica noastră privind Cookie-urile.
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
  main{
    padding-top: 70px;
  }
</style>
