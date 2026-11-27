/* ============================================================
   MOBILE NAV TOGGLE
   ============================================================ */
const navToggle = document.querySelector('.nav__toggle')
const navMenu   = document.querySelector('.nav__menu')

if (navToggle && navMenu) {
  navToggle.addEventListener('click', () => {
    const open = navToggle.getAttribute('aria-expanded') === 'true'
    navToggle.setAttribute('aria-expanded', String(!open))
    navMenu.classList.toggle('nav__menu--open')
  })

  document.addEventListener('click', e => {
    if (!navToggle.contains(e.target) && !navMenu.contains(e.target)) {
      navToggle.setAttribute('aria-expanded', 'false')
      navMenu.classList.remove('nav__menu--open')
    }
  })
}

/* ============================================================
   TERMINAL HERO ANIMATION
   ============================================================ */
const delay = ms => new Promise(r => setTimeout(r, ms))

async function typeText(el, text, speed = 55) {
  if (!el) return
  el.textContent = ''
  for (const ch of text) {
    el.textContent += ch
    await delay(speed + Math.random() * 20 - 10)
  }
}

async function animateHero() {
  const terminal = document.querySelector('[data-terminal]')
  if (!terminal) return

  const cmd1    = document.getElementById('hero-cmd')
  const cursor1 = document.getElementById('hero-cursor')
  const out1    = document.getElementById('hero-output')
  const line2   = document.getElementById('hero-line-2')
  const cmd2    = document.getElementById('hero-cmd-2')
  const cursor2 = document.getElementById('hero-cursor-2')
  const out2    = document.getElementById('hero-output-2')
  const line3   = document.getElementById('hero-line-3')

  await delay(400)

  // Type: whoami
  await typeText(cmd1, 'whoami')
  if (cursor1) cursor1.style.display = 'none'

  await delay(180)

  // Show output
  if (out1) {
    out1.removeAttribute('hidden')
    out1.style.animation = 'fadeIn .4s ease'
  }

  await delay(700)

  // Show second prompt
  if (line2) line2.removeAttribute('hidden')
  await typeText(cmd2, 'ls ./certs')
  if (cursor2) cursor2.style.display = 'none'

  await delay(180)

  // Show certs output
  if (out2) {
    out2.removeAttribute('hidden')
    out2.style.animation = 'fadeIn .4s ease'
  }

  await delay(400)

  // Show blinking cursor at end
  if (line3) line3.removeAttribute('hidden')
}

/* ============================================================
   SCROLL REVEAL
   ============================================================ */
const revealEls = document.querySelectorAll('[data-reveal]')
if (revealEls.length) {
  const revealObserver = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed')
          revealObserver.unobserve(entry.target)
        }
      })
    },
    { threshold: 0.08 }
  )
  revealEls.forEach(el => revealObserver.observe(el))
}

/* ============================================================
   DIFFICULTY FILTER (posts list)
   ============================================================ */
const filterBtns = document.querySelectorAll('.filter-btn')
const postCards  = document.querySelectorAll('.post-card')

if (filterBtns.length && postCards.length) {
  let activeFilter = 'all'
  let searchQuery  = ''

  function applyFilters() {
    postCards.forEach(card => {
      const matchDiff   = activeFilter === 'all' || card.dataset.difficulty === activeFilter
      const matchSearch = !searchQuery ||
        card.dataset.title.includes(searchQuery) ||
        card.dataset.tags.includes(searchQuery)
      card.style.display = matchDiff && matchSearch ? '' : 'none'
    })
  }

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('filter-btn--active'))
      btn.classList.add('filter-btn--active')
      activeFilter = btn.dataset.filter
      applyFilters()
    })
  })

  const searchInput = document.getElementById('post-search')
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value.trim().toLowerCase()
      applyFilters()
    })
  }
}

/* ============================================================
   ACTIVE TOC LINK ON SCROLL
   ============================================================ */
const tocLinks  = document.querySelectorAll('.toc a')
const headings  = document.querySelectorAll('.article__body h2[id], .article__body h3[id]')

if (tocLinks.length && headings.length) {
  const tocObserver = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const id = entry.target.id
          tocLinks.forEach(link => {
            const active = link.getAttribute('href') === `#${id}`
            link.classList.toggle('active', active)
          })
        }
      })
    },
    { rootMargin: `-${getComputedStyle(document.documentElement).getPropertyValue('--nav-h').trim()} 0px -65% 0px` }
  )
  headings.forEach(h => tocObserver.observe(h))
}

/* ============================================================
   INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  animateHero()
})
